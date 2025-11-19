package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Config struct {
	// Server Config
	ServerPort string `mapstructure:"SERVER_PORT" json:"SERVER_PORT"`

	// Database Config
	DatabaseDSN  string `mapstructure:"DATABASE_DSN" json:"DATABASE_DSN"`
	DatabaseType string `mapstructure:"DATABASE_TYPE" json:"DATABASE_TYPE"` // postgres, sqlite

	// JWT Config
	JWTSecret               string `mapstructure:"JWT_SECRET" json:"JWT_SECRET"`
	JWTAccessTokenExpiry    int    `mapstructure:"JWT_ACCESS_TOKEN_EXPIRY" json:"JWT_ACCESS_TOKEN_EXPIRY"`       // minutes
	JWTRefreshTokenExpiry   int    `mapstructure:"JWT_REFRESH_TOKEN_EXPIRY" json:"JWT_REFRESH_TOKEN_EXPIRY"`     // days
	JWTRefreshTokenRotation bool   `mapstructure:"JWT_REFRESH_TOKEN_ROTATION" json:"JWT_REFRESH_TOKEN_ROTATION"` // enable refresh token rotation

	// Password Config
	PasswordMinLength int `mapstructure:"PASSWORD_MIN_LENGTH" json:"PASSWORD_MIN_LENGTH"`

	// Email Config
	EmailSMTPHost     string `mapstructure:"EMAIL_SMTP_HOST" json:"EMAIL_SMTP_HOST"`
	EmailSMTPPort     int    `mapstructure:"EMAIL_SMTP_PORT" json:"EMAIL_SMTP_PORT"`
	EmailSMTPUsername string `mapstructure:"EMAIL_SMTP_USERNAME" json:"EMAIL_SMTP_USERNAME"`
	EmailSMTPPassword string `mapstructure:"EMAIL_SMTP_PASSWORD" json:"EMAIL_SMTP_PASSWORD"`
	EmailFromAddress  string `mapstructure:"EMAIL_FROM_ADDRESS" json:"EMAIL_FROM_ADDRESS"`
	EmailFromName     string `mapstructure:"EMAIL_FROM_NAME" json:"EMAIL_FROM_NAME"`
	EmailEnabled      bool   `mapstructure:"EMAIL_ENABLED" json:"EMAIL_ENABLED"`
}

func LoadConfig() (*Config, error) {
	var config Config

	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Debug().Err(err).Msg(".env file not found, using environment variables and defaults")
	}

	// Set defaults
	viper.SetDefault("SERVER_PORT", "8080")
	viper.SetDefault("DATABASE_TYPE", "sqlite")
	viper.SetDefault("DATABASE_DSN", "file:test.db?cache=shared&mode=memory")
	viper.SetDefault("JWT_ACCESS_TOKEN_EXPIRY", 15) // 15 minutes
	viper.SetDefault("JWT_REFRESH_TOKEN_EXPIRY", 7) // 7 days
	viper.SetDefault("JWT_REFRESH_TOKEN_ROTATION", true)
	viper.SetDefault("PASSWORD_MIN_LENGTH", 8)
	viper.SetDefault("EMAIL_ENABLED", false)

	// Bind environment variables
	viper.AutomaticEnv()

	// Try to read config file
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	if err := viper.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("Config file not found, using defaults and environment variables")
	}

	// Unmarshal config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate required fields
	if config.JWTSecret == "" {
		// Generate a default secret if not set (not recommended for production)
		config.JWTSecret = os.Getenv("JWT_SECRET")
		if config.JWTSecret == "" {
			return nil, fmt.Errorf("JWT_SECRET is required")
		}
	}

	log.Info().
		Str("port", config.ServerPort).
		Str("database_type", config.DatabaseType).
		Bool("email_enabled", config.EmailEnabled).
		Msg("Config loaded successfully")

	return &config, nil
}
