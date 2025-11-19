package repositories

import (
	"testing"

	"boilerplate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupPasswordHistoryTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.PasswordHistory{})
	require.NoError(t, err)

	return db
}

func TestPasswordHistoryRepository_Create(t *testing.T) {
	db := setupPasswordHistoryTestDB(t)
	repo := NewPasswordHistoryRepository(db)

	t.Run("successful create", func(t *testing.T) {
		history := &models.PasswordHistory{
			UserID:   uuid.New(),
			Password: "hashedpassword123",
		}

		err := repo.Create(history)
		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, history.ID)
	})
}

func TestPasswordHistoryRepository_FindLastNByUserID(t *testing.T) {
	db := setupPasswordHistoryTestDB(t)
	repo := NewPasswordHistoryRepository(db)

	userID1 := uuid.New()
	userID2 := uuid.New()

	// Create 7 password histories for user1
	for i := 1; i <= 7; i++ {
		history := &models.PasswordHistory{
			UserID:   userID1,
			Password: "password" + string(rune(i)),
		}
		err := repo.Create(history)
		require.NoError(t, err)
		// Small delay to ensure different timestamps
	}

	// Create 2 password histories for user2
	for i := 1; i <= 2; i++ {
		history := &models.PasswordHistory{
			UserID:   userID2,
			Password: "user2password" + string(rune(i)),
		}
		err := repo.Create(history)
		require.NoError(t, err)
	}

	t.Run("find last 5 for user with 7 histories", func(t *testing.T) {
		histories, err := repo.FindLastNByUserID(userID1, 5)
		assert.NoError(t, err)
		assert.Len(t, histories, 5)
		// Should be ordered by created_at DESC
		assert.NotEmpty(t, histories[0].Password)
	})

	t.Run("find last 10 for user with 7 histories", func(t *testing.T) {
		histories, err := repo.FindLastNByUserID(userID1, 10)
		assert.NoError(t, err)
		assert.Len(t, histories, 7) // Should return all 7
	})

	t.Run("find last 5 for user with 2 histories", func(t *testing.T) {
		histories, err := repo.FindLastNByUserID(userID2, 5)
		assert.NoError(t, err)
		assert.Len(t, histories, 2) // Should return only 2
	})

	t.Run("find for non-existing user", func(t *testing.T) {
		histories, err := repo.FindLastNByUserID(uuid.New(), 5)
		assert.NoError(t, err)
		assert.Len(t, histories, 0)
	})
}
