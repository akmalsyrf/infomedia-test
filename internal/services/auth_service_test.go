package services

import (
	"testing"

	"boilerplate/internal/config"
	"boilerplate/internal/models"
	"boilerplate/internal/repositories"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.User{}, &models.RefreshToken{}, &models.PasswordHistory{})
	require.NoError(t, err)

	return db
}

func setupTestService(t *testing.T) AuthService {
	db := setupTestDB(t)
	cfg := &config.Config{
		JWTSecret:               "test-secret-key",
		JWTAccessTokenExpiry:    15,
		JWTRefreshTokenExpiry:   7,
		JWTRefreshTokenRotation: true,
		PasswordMinLength:       8,
		EmailEnabled:            false,
	}

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewTokenRepository(db)
	passwordHistoryRepo := repositories.NewPasswordHistoryRepository(db)
	emailService := NewMockEmailService()

	return NewAuthService(cfg, userRepo, tokenRepo, passwordHistoryRepo, emailService)
}

func TestAuthService_Register(t *testing.T) {
	service := setupTestService(t)

	t.Run("successful registration", func(t *testing.T) {
		user, err := service.Register("test@example.com", "password123")
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "test@example.com", user.Email)
		assert.NotEqual(t, "password123", user.Password) // Password should be hashed
	})

	t.Run("duplicate email", func(t *testing.T) {
		_, err := service.Register("duplicate@example.com", "password123")
		assert.NoError(t, err)

		_, err = service.Register("duplicate@example.com", "password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("short password", func(t *testing.T) {
		_, err := service.Register("test2@example.com", "short")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least")
	})

	t.Run("empty email", func(t *testing.T) {
		_, err := service.Register("", "password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "email is required")
	})
}

func TestAuthService_Login(t *testing.T) {
	service := setupTestService(t)

	// Register user first
	_, err := service.Register("test@example.com", "password123")
	require.NoError(t, err)

	t.Run("successful login", func(t *testing.T) {
		response, err := service.Login("test@example.com", "password123")
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.Equal(t, "test@example.com", response.User.Email)
	})

	t.Run("invalid email", func(t *testing.T) {
		_, err := service.Login("wrong@example.com", "password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid email or password")
	})

	t.Run("invalid password", func(t *testing.T) {
		_, err := service.Login("test@example.com", "wrongpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid email or password")
	})
}

func TestAuthService_RefreshToken(t *testing.T) {
	service := setupTestService(t)

	// Register and login
	_, err := service.Register("test@example.com", "password123")
	require.NoError(t, err)

	loginResponse, err := service.Login("test@example.com", "password123")
	require.NoError(t, err)

	t.Run("successful refresh", func(t *testing.T) {
		response, err := service.RefreshToken(loginResponse.RefreshToken)
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken) // Rotation enabled
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		_, err := service.RefreshToken("invalid-token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid or expired")
	})
}

func TestAuthService_ChangePassword(t *testing.T) {
	service := setupTestService(t)

	// Register user
	user, err := service.Register("test@example.com", "password123")
	require.NoError(t, err)

	t.Run("successful password change", func(t *testing.T) {
		err := service.ChangePassword(user.ID, "password123", "newpassword123")
		assert.NoError(t, err)
	})

	t.Run("invalid old password", func(t *testing.T) {
		err := service.ChangePassword(user.ID, "wrongpassword", "newpassword123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid old password")
	})

	t.Run("short new password", func(t *testing.T) {
		err := service.ChangePassword(user.ID, "anotherpassword123", "short")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least")
	})

	t.Run("cannot reuse current password", func(t *testing.T) {
		// Create a new user for this test
		testUser, err := service.Register("test2@example.com", "testpass123")
		require.NoError(t, err)

		// Try to change password to the same password
		err = service.ChangePassword(testUser.ID, "testpass123", "testpass123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be the same as any of your last 5 passwords")
	})

	t.Run("cannot reuse password from history", func(t *testing.T) {
		// Create a new user for this test
		testUser, err := service.Register("test3@example.com", "originalpass")
		require.NoError(t, err)

		// Change password multiple times to build history
		err = service.ChangePassword(testUser.ID, "originalpass", "newpass1")
		require.NoError(t, err)

		err = service.ChangePassword(testUser.ID, "newpass1", "newpass2")
		require.NoError(t, err)

		err = service.ChangePassword(testUser.ID, "newpass2", "newpass3")
		require.NoError(t, err)

		err = service.ChangePassword(testUser.ID, "newpass3", "newpass4")
		require.NoError(t, err)

		err = service.ChangePassword(testUser.ID, "newpass4", "newpass5")
		require.NoError(t, err)

		// Now try to reuse the first password (should be in history)
		err = service.ChangePassword(testUser.ID, "newpass5", "originalpass")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be the same as any of your last 5 passwords")
	})
}

func TestAuthService_ValidateAccessToken(t *testing.T) {
	service := setupTestService(t)

	// Register and login
	_, err := service.Register("test@example.com", "password123")
	require.NoError(t, err)

	loginResponse, err := service.Login("test@example.com", "password123")
	require.NoError(t, err)

	t.Run("valid token", func(t *testing.T) {
		claims, err := service.ValidateAccessToken(loginResponse.AccessToken)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "test@example.com", claims.Email)
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := service.ValidateAccessToken("invalid-token")
		assert.Error(t, err)
	})
}

func TestPasswordHashing(t *testing.T) {
	password := "testpassword123"
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	// Verify password
	err = bcrypt.CompareHashAndPassword(hashed, []byte(password))
	assert.NoError(t, err)

	// Wrong password
	err = bcrypt.CompareHashAndPassword(hashed, []byte("wrongpassword"))
	assert.Error(t, err)
}

func TestAuthService_ChangePassword_PasswordHistoryError(t *testing.T) {
	service := setupTestService(t)

	// Register user
	user, err := service.Register("test4@example.com", "password123")
	require.NoError(t, err)

	// This test verifies that password history check works
	// and that password reuse is prevented
	t.Run("password history check prevents reuse", func(t *testing.T) {
		// Change password once
		err := service.ChangePassword(user.ID, "password123", "newpass1")
		require.NoError(t, err)

		// Try to reuse original password
		err = service.ChangePassword(user.ID, "newpass1", "password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be the same as any of your last 5 passwords")
	})
}

func TestAuthService_RefreshToken_WithoutRotation(t *testing.T) {
	// Create service with rotation disabled
	db := setupTestDB(t)
	cfg := &config.Config{
		JWTSecret:               "test-secret-key",
		JWTAccessTokenExpiry:    15,
		JWTRefreshTokenExpiry:   7,
		JWTRefreshTokenRotation: false, // Disabled
		PasswordMinLength:       8,
		EmailEnabled:            false,
	}

	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewTokenRepository(db)
	passwordHistoryRepo := repositories.NewPasswordHistoryRepository(db)
	emailService := NewMockEmailService()

	serviceNoRotation := NewAuthService(cfg, userRepo, tokenRepo, passwordHistoryRepo, emailService)

	// Register and login with new service
	_, err := serviceNoRotation.Register("test6@example.com", "password123")
	require.NoError(t, err)

	loginResponse2, err := serviceNoRotation.Login("test6@example.com", "password123")
	require.NoError(t, err)

	t.Run("refresh without rotation", func(t *testing.T) {
		response, err := serviceNoRotation.RefreshToken(loginResponse2.RefreshToken)
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.NotEmpty(t, response.AccessToken)
		assert.Empty(t, response.RefreshToken) // Should be empty when rotation disabled
	})
}

func TestAuthService_ValidateAccessToken_InvalidSigningMethod(t *testing.T) {
	service := setupTestService(t)

	// Register and login
	_, err := service.Register("test7@example.com", "password123")
	require.NoError(t, err)

	loginResponse, err := service.Login("test7@example.com", "password123")
	require.NoError(t, err)

	t.Run("validate with wrong secret", func(t *testing.T) {
		// Create a service with different secret
		db := setupTestDB(t)
		cfg := &config.Config{
			JWTSecret:               "different-secret-key",
			JWTAccessTokenExpiry:    15,
			JWTRefreshTokenExpiry:   7,
			JWTRefreshTokenRotation: true,
			PasswordMinLength:       8,
			EmailEnabled:            false,
		}

		userRepo := repositories.NewUserRepository(db)
		tokenRepo := repositories.NewTokenRepository(db)
		passwordHistoryRepo := repositories.NewPasswordHistoryRepository(db)
		emailService := NewMockEmailService()

		serviceDifferentSecret := NewAuthService(cfg, userRepo, tokenRepo, passwordHistoryRepo, emailService)

		// Try to validate token from different service
		_, err := serviceDifferentSecret.ValidateAccessToken(loginResponse.AccessToken)
		assert.Error(t, err)
	})
}
