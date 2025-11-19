package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"boilerplate/internal/models"
	"boilerplate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// MockAuthService for testing middleware
type MockAuthServiceForMiddleware struct {
	ValidateTokenFunc func(tokenString string) (*services.TokenClaims, error)
}

func (m *MockAuthServiceForMiddleware) Register(email, password string) (*models.User, error) {
	return nil, nil
}

func (m *MockAuthServiceForMiddleware) Login(email, password string) (*services.LoginResponse, error) {
	return nil, nil
}

func (m *MockAuthServiceForMiddleware) RefreshToken(refreshToken string) (*services.RefreshTokenResponse, error) {
	return nil, nil
}

func (m *MockAuthServiceForMiddleware) ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error {
	return nil
}

func (m *MockAuthServiceForMiddleware) ValidateAccessToken(tokenString string) (*services.TokenClaims, error) {
	if m.ValidateTokenFunc != nil {
		return m.ValidateTokenFunc(tokenString)
	}
	return nil, nil
}

func TestAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		authHeader     string
		mockService    *MockAuthServiceForMiddleware
		expectedStatus int
		expectedBody   string
		shouldSetCtx  bool
	}{
		{
			name:       "missing authorization header",
			authHeader: "",
			mockService: &MockAuthServiceForMiddleware{},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "authorization header required",
		},
		{
			name:       "invalid authorization header format - no bearer",
			authHeader: "InvalidToken123",
			mockService: &MockAuthServiceForMiddleware{},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid authorization header format",
		},
		{
			name:       "invalid authorization header format - too many parts",
			authHeader: "Bearer token extra",
			mockService: &MockAuthServiceForMiddleware{},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid authorization header format",
		},
		{
			name:       "expired token",
			authHeader: "Bearer expired-token",
			mockService: &MockAuthServiceForMiddleware{
				ValidateTokenFunc: func(tokenString string) (*services.TokenClaims, error) {
					return nil, jwt.ErrTokenExpired
				},
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "access token expired",
		},
		{
			name:       "invalid token",
			authHeader: "Bearer invalid-token",
			mockService: &MockAuthServiceForMiddleware{
				ValidateTokenFunc: func(tokenString string) (*services.TokenClaims, error) {
					return nil, assert.AnError
				},
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "invalid or expired token",
		},
		{
			name:       "valid token",
			authHeader: "Bearer valid-token",
			mockService: &MockAuthServiceForMiddleware{
				ValidateTokenFunc: func(tokenString string) (*services.TokenClaims, error) {
					return &services.TokenClaims{
						UserID: uuid.New(),
						Email:  "test@example.com",
					}, nil
				},
			},
			expectedStatus: http.StatusOK,
			shouldSetCtx:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(AuthMiddleware(tt.mockService))
			router.GET("/test", func(c *gin.Context) {
				userID, exists := c.Get("user_id")
				if tt.shouldSetCtx {
					assert.True(t, exists)
					assert.NotNil(t, userID)
					
					email, exists := c.Get("email")
					assert.True(t, exists)
					assert.Equal(t, "test@example.com", email)
				}
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestAuthMiddleware_ExpiredTokenInMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	mockService := &MockAuthServiceForMiddleware{
		ValidateTokenFunc: func(tokenString string) (*services.TokenClaims, error) {
			return nil, assert.AnError // Error that contains "expired" in message
		},
	}

	// Create an error that contains "expired" in the message
	expiredError := &testError{message: "token is expired"}
	mockService.ValidateTokenFunc = func(tokenString string) (*services.TokenClaims, error) {
		return nil, expiredError
	}

	router.Use(AuthMiddleware(mockService))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "access token expired")
}

type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

