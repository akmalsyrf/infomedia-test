package repositories

import (
	"boilerplate/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PasswordHistoryRepository interface {
	Create(history *models.PasswordHistory) error
	FindLastNByUserID(userID uuid.UUID, n int) ([]*models.PasswordHistory, error)
}

type passwordHistoryRepository struct {
	db *gorm.DB
}

func NewPasswordHistoryRepository(db *gorm.DB) PasswordHistoryRepository {
	return &passwordHistoryRepository{db: db}
}

func (r *passwordHistoryRepository) Create(history *models.PasswordHistory) error {
	return r.db.Create(history).Error
}

func (r *passwordHistoryRepository) FindLastNByUserID(userID uuid.UUID, n int) ([]*models.PasswordHistory, error) {
	var histories []*models.PasswordHistory
	err := r.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(n).
		Find(&histories).Error
	if err != nil {
		return nil, err
	}
	return histories, nil
}
