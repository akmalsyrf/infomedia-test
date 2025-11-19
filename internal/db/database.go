package db

import (
	"fmt"

	"boilerplate/internal/config"
	"boilerplate/internal/models"

	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewDatabase(cfg *config.Config) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	switch cfg.DatabaseType {
	case "postgres":
		db, err = gorm.Open(postgres.Open(cfg.DatabaseDSN), gormConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to postgres: %w", err)
		}
		log.Info().Msg("Connected to PostgreSQL database")
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(cfg.DatabaseDSN), gormConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to sqlite: %w", err)
		}
		log.Info().Msg("Connected to SQLite database")
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.DatabaseType)
	}

	// Auto migrate
	if err := db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.PasswordHistory{},
	); err != nil {
		return nil, fmt.Errorf("failed to auto migrate: %w", err)
	}

	log.Info().Msg("Database migration completed")

	return db, nil
}
