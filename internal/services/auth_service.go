package services

import (
	"errors"
	"fmt"
	"time"

	"boilerplate/internal/config"
	"boilerplate/internal/models"
	"boilerplate/internal/repositories"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Register(email, password string) (*models.User, error)
	Login(email, password string) (*LoginResponse, error)
	RefreshToken(refreshToken string) (*RefreshTokenResponse, error)
	ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error
	ValidateAccessToken(tokenString string) (*TokenClaims, error)
}

type authService struct {
	config              *config.Config
	userRepo            repositories.UserRepository
	tokenRepo           repositories.TokenRepository
	passwordHistoryRepo repositories.PasswordHistoryRepository
	emailService        EmailService
}

type LoginResponse struct {
	AccessToken          string       `json:"access_token"`
	AccessTokenExpiresAt time.Time    `json:"access_token_expires_at"` // in time
	RefreshToken         string       `json:"refresh_token"`
	User                 *models.User `json:"user"`
}

type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"` // Only if rotation enabled
}

type TokenClaims struct {
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
	jwt.RegisteredClaims
}

func NewAuthService(
	cfg *config.Config,
	userRepo repositories.UserRepository,
	tokenRepo repositories.TokenRepository,
	passwordHistoryRepo repositories.PasswordHistoryRepository,
	emailService EmailService,
) AuthService {
	return &authService{
		config:              cfg,
		userRepo:            userRepo,
		tokenRepo:           tokenRepo,
		passwordHistoryRepo: passwordHistoryRepo,
		emailService:        emailService,
	}
}

func (s *authService) Register(email, password string) (*models.User, error) {
	// Validate input
	if email == "" {
		return nil, errors.New("email is required")
	}
	if len(password) < s.config.PasswordMinLength {
		return nil, fmt.Errorf("password must be at least %d characters", s.config.PasswordMinLength)
	}

	// Check if user already exists
	existingUser, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}
	if existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		Email:    email,
		Password: string(hashedPassword),
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Send email notification (async, don't fail if email fails)
	if s.config.EmailEnabled {
		go func() {
			if err := s.emailService.SendRegistrationEmail(user.Email, password); err != nil {
				log.Warn().Err(err).Msg("Failed to send registration email")
			}
		}()
	} else {
		log.Info().Msg("Email is triggered but email is disabled")
	}

	return user, nil
}

func (s *authService) Login(email, password string) (*LoginResponse, error) {
	// Find user
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return nil, errors.New("invalid email or password")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid email or password")
	}

	// Generate tokens
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Save refresh token to database
	refreshTokenModel := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().AddDate(0, 0, s.config.JWTRefreshTokenExpiry),
	}
	if err := s.tokenRepo.Create(refreshTokenModel); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &LoginResponse{
		AccessToken:          accessToken,
		AccessTokenExpiresAt: time.Now().Add(time.Duration(s.config.JWTAccessTokenExpiry) * time.Minute),
		RefreshToken:         refreshToken,
		User:                 user,
	}, nil
}

func (s *authService) RefreshToken(refreshToken string) (*RefreshTokenResponse, error) {
	// Find refresh token in database
	tokenModel, err := s.tokenRepo.FindByToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to find refresh token: %w", err)
	}
	if tokenModel == nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	// Get user
	user, err := s.userRepo.FindByID(tokenModel.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	// Generate new access token
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	response := &RefreshTokenResponse{
		AccessToken: accessToken,
	}

	// Refresh token rotation
	if s.config.JWTRefreshTokenRotation {
		// Delete old refresh token
		if err := s.tokenRepo.DeleteByToken(refreshToken); err != nil {
			log.Warn().Err(err).Msg("Failed to delete old refresh token")
		}

		// Generate new refresh token
		newRefreshToken, err := s.generateRefreshToken(user)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new refresh token: %w", err)
		}

		// Save new refresh token
		newTokenModel := &models.RefreshToken{
			UserID:    user.ID,
			Token:     newRefreshToken,
			ExpiresAt: time.Now().AddDate(0, 0, s.config.JWTRefreshTokenExpiry),
		}
		if err := s.tokenRepo.Create(newTokenModel); err != nil {
			return nil, fmt.Errorf("failed to save new refresh token: %w", err)
		}

		response.RefreshToken = newRefreshToken
	}

	return response, nil
}

func (s *authService) ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error {
	// Validate new password
	if len(newPassword) < s.config.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", s.config.PasswordMinLength)
	}

	// Get user
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return errors.New("user not found")
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return errors.New("invalid old password")
	}

	// Check if new password matches any of the last 5 passwords
	passwordHistories, err := s.passwordHistoryRepo.FindLastNByUserID(userID, 5)
	if err != nil {
		return fmt.Errorf("failed to check password history: %w", err)
	}

	// Check against current password and last 5 passwords in history
	passwordsToCheck := []string{user.Password} // Current password
	for _, history := range passwordHistories {
		passwordsToCheck = append(passwordsToCheck, history.Password)
	}

	for _, hashedPassword := range passwordsToCheck {
		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(newPassword)); err == nil {
			return errors.New("new password cannot be the same as any of your last 5 passwords")
		}
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Save old password to history before updating
	oldPasswordHistory := &models.PasswordHistory{
		UserID:   userID,
		Password: user.Password, // Save the hashed old password
	}
	if err := s.passwordHistoryRepo.Create(oldPasswordHistory); err != nil {
		log.Warn().Err(err).Msg("Failed to save password to history")
		// Continue with password update even if history save fails
	}

	// Update user password
	user.Password = string(hashedPassword)
	if err := s.userRepo.Update(user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Invalidate all refresh tokens for security
	if err := s.tokenRepo.DeleteByUserID(userID); err != nil {
		log.Warn().Err(err).Msg("Failed to invalidate refresh tokens")
	}

	return nil
}

func (s *authService) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (s *authService) generateAccessToken(user *models.User) (string, error) {
	expiresAt := time.Now().Add(time.Duration(s.config.JWTAccessTokenExpiry) * time.Minute)
	claims := &TokenClaims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *authService) generateRefreshToken(_ *models.User) (string, error) {
	// Generate a random token
	token := uuid.New().String() + uuid.New().String()
	return token, nil
}
