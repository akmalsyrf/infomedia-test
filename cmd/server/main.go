package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"boilerplate/generated/api"
	"boilerplate/internal/composers"
	"boilerplate/internal/config"
	"boilerplate/internal/db"
	"boilerplate/internal/http/middleware"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

func main() {
	// Setup logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Load config
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	// Initialize database
	database, err := db.NewDatabase(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize database")
	}

	// Initialize handlers and services using Wire
	authHandler, err := composers.InitializeAuthHandler(database, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize handlers")
	}

	authService, err := composers.InitializeAuthService(database, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize auth service")
	}

	// Setup Gin router
	if cfg.ServerPort == "8080" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.LoggerMiddleware())

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Create auth middleware function
	authMiddlewareFunc := func(c *gin.Context) {
		// Check if this route requires authentication (has BearerAuthScopes set)
		scopes, exists := c.Get(api.BearerAuthScopes)
		if exists && scopes != nil {
			// This is a protected route, apply auth middleware
			middleware.AuthMiddleware(authService)(c)
		} else {
			// Public route, continue
			c.Next()
		}
	}

	// Register API routes using generated code with auth middleware
	api.RegisterHandlersWithOptions(router, authHandler, api.GinServerOptions{
		Middlewares: []api.MiddlewareFunc{
			authMiddlewareFunc,
		},
		ErrorHandler: func(c *gin.Context, err error, statusCode int) {
			// Check if it's a validation error
			if strings.Contains(err.Error(), "binding") || strings.Contains(err.Error(), "validation") {
				c.JSON(statusCode, api.Error400Response{
					Error: err.Error(),
				})
			} else {
				c.JSON(statusCode, gin.H{"error": err.Error()})
			}
		},
	})

	// Create HTTP server
	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	// Setup graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		log.Info().Str("address", addr).Msg("Starting server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	// Wait for interrupt signal
	<-quit
	log.Info().Msg("Shutting down server...")

	// Cleanup function
	cleanup(database)

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server forced to shutdown")
	} else {
		log.Info().Msg("Server exited gracefully")
	}
}

// cleanup performs cleanup operations for graceful shutdown
func cleanup(database *gorm.DB) {
	log.Info().Msg("Cleaning up resources...")

	// Close database connection
	if database != nil {
		sqlDB, err := database.DB()
		if err != nil {
			log.Error().Err(err).Msg("Failed to get database connection")
		} else {
			if err := sqlDB.Close(); err != nil {
				log.Error().Err(err).Msg("Failed to close database connection")
			} else {
				log.Info().Msg("Database connection closed")
			}
		}
	}

	log.Info().Msg("Cleanup completed")
}
