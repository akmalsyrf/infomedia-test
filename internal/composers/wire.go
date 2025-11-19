//go:build wireinject
// +build wireinject

package composers

import (
	"boilerplate/internal/config"
	"boilerplate/internal/handlers"
	"boilerplate/internal/repositories"
	"boilerplate/internal/services"

	"github.com/google/wire"
	"gorm.io/gorm"
)

func InitializeAuthHandler(db *gorm.DB, cfg *config.Config) (*handlers.AuthHandler, error) {
	wire.Build(
		// Repositories
		repositories.NewUserRepository,
		repositories.NewTokenRepository,
		repositories.NewPasswordHistoryRepository,

		// Services
		services.NewEmailService,
		services.NewAuthService,

		// Handlers
		handlers.NewAuthHandler,
	)

	return nil, nil
}

func InitializeAuthService(db *gorm.DB, cfg *config.Config) (services.AuthService, error) {
	wire.Build(
		// Repositories
		repositories.NewUserRepository,
		repositories.NewTokenRepository,
		repositories.NewPasswordHistoryRepository,

		// Services
		services.NewEmailService,
		services.NewAuthService,
	)

	return nil, nil
}
