package repositories

import (
	"errors"
	"time"

	"boilerplate/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type TokenRepository interface {
	Create(token *models.RefreshToken) error
	FindByToken(token string) (*models.RefreshToken, error)
	DeleteByToken(token string) error
	DeleteByUserID(userID uuid.UUID) error
	DeleteExpired() error
}

type tokenRepository struct {
	db *gorm.DB
}

func NewTokenRepository(db *gorm.DB) TokenRepository {
	return &tokenRepository{db: db}
}

func (r *tokenRepository) Create(token *models.RefreshToken) error {
	return r.db.Create(token).Error
}

func (r *tokenRepository) FindByToken(token string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	err := r.db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&refreshToken).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &refreshToken, nil
}

func (r *tokenRepository) DeleteByToken(token string) error {
	return r.db.Where("token = ?", token).Delete(&models.RefreshToken{}).Error
}

func (r *tokenRepository) DeleteByUserID(userID uuid.UUID) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.RefreshToken{}).Error
}

func (r *tokenRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{}).Error
}
