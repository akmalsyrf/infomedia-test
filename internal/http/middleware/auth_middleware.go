package middleware

import (
	"errors"
	"net/http"
	"strings"

	"boilerplate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

func AuthMiddleware(authService services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			c.Abort()
			return
		}

		// Check Bearer token format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := authService.ValidateAccessToken(tokenString)
		if err != nil {
			log.Debug().Err(err).Msg("Token validation failed")

			// Check if token is expired
			if errors.Is(err, jwt.ErrTokenExpired) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "access token expired"})
				c.Abort()
				return
			}

			// Check for expiration error in error message (fallback for wrapped errors)
			if strings.Contains(err.Error(), "expired") || strings.Contains(strings.ToLower(err.Error()), "token is expired") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "access token expired"})
				c.Abort()
				return
			}

			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		// Set user info in context
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)

		c.Next()
	}
}
