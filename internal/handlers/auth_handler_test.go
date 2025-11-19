package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"boilerplate/generated/api"
	"boilerplate/internal/models"
	"boilerplate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockError is a simple error type for testing
type mockError struct {
	message string
}

func (e *mockError) Error() string {
	return e.message
}

// MockAuthService is a mock implementation of AuthService for testing
type MockAuthService struct {
	RegisterFunc       func(email, password string) (*models.User, error)
	LoginFunc          func(email, password string) (*services.LoginResponse, error)
	RefreshTokenFunc   func(refreshToken string) (*services.RefreshTokenResponse, error)
	ChangePasswordFunc func(userID uuid.UUID, oldPassword, newPassword string) error
	ValidateTokenFunc  func(tokenString string) (*services.TokenClaims, error)
}

func (m *MockAuthService) Register(email, password string) (*models.User, error) {
	if m.RegisterFunc != nil {
		return m.RegisterFunc(email, password)
	}
	return nil, nil
}

func (m *MockAuthService) Login(email, password string) (*services.LoginResponse, error) {
	if m.LoginFunc != nil {
		return m.LoginFunc(email, password)
	}
	return nil, nil
}

func (m *MockAuthService) RefreshToken(refreshToken string) (*services.RefreshTokenResponse, error) {
	if m.RefreshTokenFunc != nil {
		return m.RefreshTokenFunc(refreshToken)
	}
	return nil, nil
}

func (m *MockAuthService) ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error {
	if m.ChangePasswordFunc != nil {
		return m.ChangePasswordFunc(userID, oldPassword, newPassword)
	}
	return nil
}

func (m *MockAuthService) ValidateAccessToken(tokenString string) (*services.TokenClaims, error) {
	if m.ValidateTokenFunc != nil {
		return m.ValidateTokenFunc(tokenString)
	}
	return nil, nil
}

func setupTestRouter(handler *AuthHandler, middleware ...gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add middleware if provided
	for _, mw := range middleware {
		router.Use(mw)
	}

	// Register routes manually for testing
	router.POST("/api/v1/register", handler.V1AuthRegisterPost)
	router.POST("/api/v1/login", handler.V1AuthLoginPost)
	router.POST("/api/v1/refresh", handler.V1AuthRefreshPost)
	router.POST("/api/v1/change-password", handler.V1AuthChangePasswordPost)

	return router
}

func TestAuthHandler_V1AuthRegisterPost(t *testing.T) {
	tests := []struct {
		name             string
		requestBody      interface{}
		mockService      *MockAuthService
		expectedStatus   int
		validateResponse func(t *testing.T, body map[string]interface{})
	}{
		{
			name: "successful registration",
			requestBody: api.V1AuthRegisterPostJSONRequestBody{
				Email:    openapi_types.Email("test@example.com"),
				Password: "password123",
			},
			mockService: &MockAuthService{
				RegisterFunc: func(email, password string) (*models.User, error) {
					userID := uuid.New()
					return &models.User{
						ID:    userID,
						Email: email,
					}, nil
				},
			},
			expectedStatus: http.StatusCreated,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "User registered successfully", body["message"])
				user, ok := body["user"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "test@example.com", user["email"])
				assert.NotEmpty(t, user["id"])
			},
		},
		{
			name: "duplicate email",
			requestBody: api.V1AuthRegisterPostJSONRequestBody{
				Email:    openapi_types.Email("duplicate@example.com"),
				Password: "password123",
			},
			mockService: &MockAuthService{
				RegisterFunc: func(email, password string) (*models.User, error) {
					return nil, assert.AnError
				},
			},
			expectedStatus: http.StatusBadRequest,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.NotNil(t, body["error"])
			},
		},
		{
			name: "duplicate email - conflict",
			requestBody: api.V1AuthRegisterPostJSONRequestBody{
				Email:    openapi_types.Email("duplicate@example.com"),
				Password: "password123",
			},
			mockService: &MockAuthService{
				RegisterFunc: func(email, password string) (*models.User, error) {
					return nil, &mockError{message: "user with this email already exists"}
				},
			},
			expectedStatus: http.StatusConflict,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, body["error"], "user with this email already exists")
			},
		},
		{
			name: "invalid request body",
			requestBody: map[string]interface{}{
				"invalid": "data",
			},
			mockService:    &MockAuthService{},
			expectedStatus: http.StatusBadRequest,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.NotNil(t, body["error"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewAuthHandler(tt.mockService)
			router := setupTestRouter(handler)

			bodyBytes, err := json.Marshal(tt.requestBody)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var responseBody map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &responseBody)
			require.NoError(t, err)

			if tt.validateResponse != nil {
				tt.validateResponse(t, responseBody)
			}
		})
	}
}

func TestAuthHandler_V1AuthLoginPost(t *testing.T) {
	userID := uuid.New()
	tests := []struct {
		name             string
		requestBody      interface{}
		mockService      *MockAuthService
		expectedStatus   int
		validateResponse func(t *testing.T, body map[string]interface{})
	}{
		{
			name: "successful login",
			requestBody: api.V1AuthLoginPostJSONRequestBody{
				Email:    openapi_types.Email("test@example.com"),
				Password: "password123",
			},
			mockService: &MockAuthService{
				LoginFunc: func(email, password string) (*services.LoginResponse, error) {
					return &services.LoginResponse{
						AccessToken:  "access-token-123",
						RefreshToken: "refresh-token-123",
						User: &models.User{
							ID:    userID,
							Email: email,
						},
					}, nil
				},
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "access-token-123", body["access_token"])
				assert.Equal(t, "refresh-token-123", body["refresh_token"])
				user, ok := body["user"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "test@example.com", user["email"])
			},
		},
		{
			name: "invalid credentials",
			requestBody: api.V1AuthLoginPostJSONRequestBody{
				Email:    openapi_types.Email("test@example.com"),
				Password: "wrongpassword",
			},
			mockService: &MockAuthService{
				LoginFunc: func(email, password string) (*services.LoginResponse, error) {
					return nil, assert.AnError
				},
			},
			expectedStatus: http.StatusUnauthorized,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "invalid email or password", body["error"])
			},
		},
		{
			name: "invalid request body",
			requestBody: map[string]interface{}{
				"invalid": "data",
			},
			mockService:    &MockAuthService{},
			expectedStatus: http.StatusBadRequest,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.NotNil(t, body["error"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewAuthHandler(tt.mockService)
			router := setupTestRouter(handler)

			bodyBytes, err := json.Marshal(tt.requestBody)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var responseBody map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &responseBody)
			require.NoError(t, err)

			if tt.validateResponse != nil {
				tt.validateResponse(t, responseBody)
			}
		})
	}
}

func TestAuthHandler_V1AuthRefreshPost(t *testing.T) {
	tests := []struct {
		name             string
		requestBody      interface{}
		mockService      *MockAuthService
		expectedStatus   int
		validateResponse func(t *testing.T, body map[string]interface{})
	}{
		{
			name: "successful refresh with token rotation",
			requestBody: api.V1AuthRefreshPostJSONRequestBody{
				RefreshToken: "valid-refresh-token",
			},
			mockService: &MockAuthService{
				RefreshTokenFunc: func(refreshToken string) (*services.RefreshTokenResponse, error) {
					return &services.RefreshTokenResponse{
						AccessToken:  "new-access-token",
						RefreshToken: "new-refresh-token",
					}, nil
				},
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "new-access-token", body["access_token"])
				assert.Equal(t, "new-refresh-token", body["refresh_token"])
			},
		},
		{
			name: "successful refresh without token rotation",
			requestBody: api.V1AuthRefreshPostJSONRequestBody{
				RefreshToken: "valid-refresh-token",
			},
			mockService: &MockAuthService{
				RefreshTokenFunc: func(refreshToken string) (*services.RefreshTokenResponse, error) {
					return &services.RefreshTokenResponse{
						AccessToken: "new-access-token",
					}, nil
				},
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "new-access-token", body["access_token"])
				// refresh_token should be nil or not present
				refreshToken, exists := body["refresh_token"]
				if exists {
					assert.Nil(t, refreshToken)
				}
			},
		},
		{
			name: "invalid refresh token",
			requestBody: api.V1AuthRefreshPostJSONRequestBody{
				RefreshToken: "invalid-token",
			},
			mockService: &MockAuthService{
				RefreshTokenFunc: func(refreshToken string) (*services.RefreshTokenResponse, error) {
					return nil, assert.AnError
				},
			},
			expectedStatus: http.StatusUnauthorized,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "invalid or expired refresh token", body["error"])
			},
		},
		{
			name: "invalid request body",
			requestBody: map[string]interface{}{
				"invalid": "data",
			},
			mockService:    &MockAuthService{},
			expectedStatus: http.StatusBadRequest,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.NotNil(t, body["error"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewAuthHandler(tt.mockService)
			router := setupTestRouter(handler)

			bodyBytes, err := json.Marshal(tt.requestBody)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var responseBody map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &responseBody)
			require.NoError(t, err)

			if tt.validateResponse != nil {
				tt.validateResponse(t, responseBody)
			}
		})
	}
}

func TestAuthHandler_V1AuthChangePasswordPost(t *testing.T) {
	userID := uuid.New()
	tests := []struct {
		name             string
		requestBody      interface{}
		setupContext     func(c *gin.Context)
		mockService      *MockAuthService
		expectedStatus   int
		validateResponse func(t *testing.T, body map[string]interface{})
	}{
		{
			name: "successful password change",
			requestBody: api.V1AuthChangePasswordPostJSONRequestBody{
				OldPassword: "oldpassword123",
				NewPassword: "newpassword123",
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", userID)
			},
			mockService: &MockAuthService{
				ChangePasswordFunc: func(userID uuid.UUID, oldPassword, newPassword string) error {
					return nil
				},
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "Password changed successfully", body["message"])
			},
		},
		{
			name: "invalid old password",
			requestBody: api.V1AuthChangePasswordPostJSONRequestBody{
				OldPassword: "wrongpassword",
				NewPassword: "newpassword123",
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", userID)
			},
			mockService: &MockAuthService{
				ChangePasswordFunc: func(userID uuid.UUID, oldPassword, newPassword string) error {
					return &mockError{message: "invalid old password"}
				},
			},
			expectedStatus: http.StatusUnauthorized,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, body["error"], "invalid old password")
			},
		},
		{
			name: "unauthorized - no user_id in context",
			requestBody: api.V1AuthChangePasswordPostJSONRequestBody{
				OldPassword: "oldpassword123",
				NewPassword: "newpassword123",
			},
			setupContext: func(c *gin.Context) {
				// Don't set user_id
			},
			mockService:    &MockAuthService{},
			expectedStatus: http.StatusUnauthorized,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "unauthorized", body["error"])
			},
		},
		{
			name: "invalid user_id type in context",
			requestBody: api.V1AuthChangePasswordPostJSONRequestBody{
				OldPassword: "oldpassword123",
				NewPassword: "newpassword123",
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "not-a-uuid")
			},
			mockService:    &MockAuthService{},
			expectedStatus: http.StatusInternalServerError,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "invalid user id", body["error"])
			},
		},
		{
			name: "invalid request body",
			requestBody: map[string]interface{}{
				"invalid": "data",
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", userID)
			},
			mockService:    &MockAuthService{},
			expectedStatus: http.StatusBadRequest,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.NotNil(t, body["error"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewAuthHandler(tt.mockService)

			// Create middleware to set context
			var middleware []gin.HandlerFunc
			if tt.setupContext != nil {
				middleware = append(middleware, func(c *gin.Context) {
					tt.setupContext(c)
					c.Next()
				})
			}

			router := setupTestRouter(handler, middleware...)

			bodyBytes, err := json.Marshal(tt.requestBody)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/change-password", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var responseBody map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &responseBody)
			require.NoError(t, err)

			if tt.validateResponse != nil {
				tt.validateResponse(t, responseBody)
			}
		})
	}
}

func TestAuthHandler_V1AuthMeGet(t *testing.T) {
	userID := uuid.New()
	email := "test@example.com"
	
	tests := []struct {
		name             string
		setupContext     func(c *gin.Context)
		expectedStatus   int
		validateResponse func(t *testing.T, body map[string]interface{})
	}{
		{
			name: "successful get user info",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", userID)
				c.Set("email", email)
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, email, body["email"])
				assert.Equal(t, userID.String(), body["id"])
			},
		},
		{
			name: "unauthorized - no user_id in context",
			setupContext: func(c *gin.Context) {
				c.Set("email", email)
			},
			expectedStatus: http.StatusUnauthorized,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "unauthorized", body["error"])
			},
		},
		{
			name: "unauthorized - no email in context",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", userID)
			},
			expectedStatus: http.StatusUnauthorized,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "unauthorized", body["error"])
			},
		},
		{
			name: "unauthorized - no context values",
			setupContext: func(c *gin.Context) {
			},
			expectedStatus: http.StatusUnauthorized,
			validateResponse: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "unauthorized", body["error"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewAuthHandler(&MockAuthService{})

			var middleware []gin.HandlerFunc
			if tt.setupContext != nil {
				middleware = append(middleware, func(c *gin.Context) {
					tt.setupContext(c)
					c.Next()
				})
			}

			gin.SetMode(gin.TestMode)
			router := gin.New()
			for _, mw := range middleware {
				router.Use(mw)
			}
			router.GET("/api/v1/me", handler.V1AuthMeGet)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var responseBody map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &responseBody)
			require.NoError(t, err)

			if tt.validateResponse != nil {
				tt.validateResponse(t, responseBody)
			}
		})
	}
}
