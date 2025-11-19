package repositories

import (
	"testing"
	"time"

	"boilerplate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTokenTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.RefreshToken{})
	require.NoError(t, err)

	return db
}

func TestTokenRepository_Create(t *testing.T) {
	db := setupTokenTestDB(t)
	repo := NewTokenRepository(db)

	t.Run("successful create", func(t *testing.T) {
		token := &models.RefreshToken{
			UserID:    uuid.New(),
			Token:     "test-token-123",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		err := repo.Create(token)
		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, token.ID)
	})
}

func TestTokenRepository_FindByToken(t *testing.T) {
	db := setupTokenTestDB(t)
	repo := NewTokenRepository(db)

	userID := uuid.New()
	validToken := "valid-token-123"
	expiredToken := "expired-token-123"

	// Create valid token
	valid := &models.RefreshToken{
		UserID:    userID,
		Token:     validToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := repo.Create(valid)
	require.NoError(t, err)

	// Create expired token
	expired := &models.RefreshToken{
		UserID:    userID,
		Token:     expiredToken,
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired
	}
	err = repo.Create(expired)
	require.NoError(t, err)

	t.Run("find valid token", func(t *testing.T) {
		found, err := repo.FindByToken(validToken)
		assert.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, validToken, found.Token)
	})

	t.Run("find expired token", func(t *testing.T) {
		found, err := repo.FindByToken(expiredToken)
		assert.NoError(t, err)
		assert.Nil(t, found) // Should return nil for expired tokens
	})

	t.Run("find non-existing token", func(t *testing.T) {
		found, err := repo.FindByToken("non-existing-token")
		assert.NoError(t, err)
		assert.Nil(t, found)
	})
}

func TestTokenRepository_DeleteByToken(t *testing.T) {
	db := setupTokenTestDB(t)
	repo := NewTokenRepository(db)

	userID := uuid.New()
	token := "delete-token-123"

	// Create token
	tokenModel := &models.RefreshToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := repo.Create(tokenModel)
	require.NoError(t, err)

	t.Run("successful delete", func(t *testing.T) {
		err := repo.DeleteByToken(token)
		assert.NoError(t, err)

		// Verify deletion
		found, err := repo.FindByToken(token)
		assert.NoError(t, err)
		assert.Nil(t, found)
	})
}

func TestTokenRepository_DeleteByUserID(t *testing.T) {
	db := setupTokenTestDB(t)
	repo := NewTokenRepository(db)

	userID1 := uuid.New()
	userID2 := uuid.New()

	// Create tokens for user1
	token1 := &models.RefreshToken{
		UserID:    userID1,
		Token:     "token1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := repo.Create(token1)
	require.NoError(t, err)

	token2 := &models.RefreshToken{
		UserID:    userID1,
		Token:     "token2",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err = repo.Create(token2)
	require.NoError(t, err)

	// Create token for user2
	token3 := &models.RefreshToken{
		UserID:    userID2,
		Token:     "token3",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err = repo.Create(token3)
	require.NoError(t, err)

	t.Run("delete all tokens for user", func(t *testing.T) {
		err := repo.DeleteByUserID(userID1)
		assert.NoError(t, err)

		// Verify user1 tokens are deleted
		found1, err := repo.FindByToken("token1")
		assert.NoError(t, err)
		assert.Nil(t, found1)

		found2, err := repo.FindByToken("token2")
		assert.NoError(t, err)
		assert.Nil(t, found2)

		// Verify user2 token still exists
		found3, err := repo.FindByToken("token3")
		assert.NoError(t, err)
		assert.NotNil(t, found3)
	})
}

func TestTokenRepository_DeleteExpired(t *testing.T) {
	db := setupTokenTestDB(t)
	repo := NewTokenRepository(db)

	userID := uuid.New()

	// Create expired token
	expired := &models.RefreshToken{
		UserID:    userID,
		Token:     "expired-token",
		ExpiresAt: time.Now().Add(-24 * time.Hour),
	}
	err := repo.Create(expired)
	require.NoError(t, err)

	// Create valid token
	valid := &models.RefreshToken{
		UserID:    userID,
		Token:     "valid-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err = repo.Create(valid)
	require.NoError(t, err)

	t.Run("delete expired tokens", func(t *testing.T) {
		err := repo.DeleteExpired()
		assert.NoError(t, err)

		// Verify expired token is deleted
		// Note: FindByToken filters by expires_at, so we check directly
		var count int64
		db.Model(&models.RefreshToken{}).Where("token = ?", "expired-token").Count(&count)
		assert.Equal(t, int64(0), count)

		// Verify valid token still exists
		foundValid, err := repo.FindByToken("valid-token")
		assert.NoError(t, err)
		assert.NotNil(t, foundValid)
	})
}

