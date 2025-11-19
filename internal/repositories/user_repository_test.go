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

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.User{})
	require.NoError(t, err)

	return db
}

func TestUserRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	t.Run("successful create", func(t *testing.T) {
		user := &models.User{
			Email:    "test@example.com",
			Password: "hashedpassword",
		}

		err := repo.Create(user)
		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, user.ID)
	})

	t.Run("create duplicate email", func(t *testing.T) {
		user1 := &models.User{
			Email:    "duplicate@example.com",
			Password: "password1",
		}
		err := repo.Create(user1)
		require.NoError(t, err)

		user2 := &models.User{
			Email:    "duplicate@example.com",
			Password: "password2",
		}
		err = repo.Create(user2)
		assert.Error(t, err)
	})
}

func TestUserRepository_FindByEmail(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	// Create test user
	user := &models.User{
		Email:    "find@example.com",
		Password: "hashedpassword",
	}
	err := repo.Create(user)
	require.NoError(t, err)

	t.Run("find existing user", func(t *testing.T) {
		found, err := repo.FindByEmail("find@example.com")
		assert.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "find@example.com", found.Email)
		assert.Equal(t, user.ID, found.ID)
	})

	t.Run("find non-existing user", func(t *testing.T) {
		found, err := repo.FindByEmail("notfound@example.com")
		assert.NoError(t, err)
		assert.Nil(t, found)
	})
}

func TestUserRepository_FindByID(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	// Create test user
	user := &models.User{
		Email:    "findbyid@example.com",
		Password: "hashedpassword",
	}
	err := repo.Create(user)
	require.NoError(t, err)

	t.Run("find existing user", func(t *testing.T) {
		found, err := repo.FindByID(user.ID)
		assert.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, user.ID, found.ID)
		assert.Equal(t, "findbyid@example.com", found.Email)
	})

	t.Run("find non-existing user", func(t *testing.T) {
		nonExistentID := uuid.New()
		found, err := repo.FindByID(nonExistentID)
		assert.NoError(t, err)
		assert.Nil(t, found)
	})
}

func TestUserRepository_Update(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	// Create test user
	user := &models.User{
		Email:    "update@example.com",
		Password: "oldpassword",
	}
	err := repo.Create(user)
	require.NoError(t, err)

	t.Run("successful update", func(t *testing.T) {
		user.Password = "newpassword"
		err := repo.Update(user)
		assert.NoError(t, err)

		// Verify update
		updated, err := repo.FindByID(user.ID)
		require.NoError(t, err)
		assert.Equal(t, "newpassword", updated.Password)
	})
}

