package handlers

import (
	"net/http"

	"boilerplate/generated/api"
	"boilerplate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

type AuthHandler struct {
	authService services.AuthService
}

func NewAuthHandler(authService services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Implement ServerInterface from generated code
var _ api.ServerInterface = (*AuthHandler)(nil)

func (h *AuthHandler) V1AuthRegisterPost(c *gin.Context) {
	var req api.V1AuthRegisterPostJSONRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.Error400Response{
			Error: err.Error(),
		})
		return
	}

	user, err := h.authService.Register(string(req.Email), req.Password)
	if err != nil {
		if err.Error() == "user with this email already exists" {
			c.JSON(http.StatusConflict, api.Error409Response{
				Error: err.Error(),
			})
			return
		}
		c.JSON(http.StatusBadRequest, api.Error400Response{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, api.V1AuthRegisterPost201Response{
		Message: "User registered successfully",
		User: struct {
			Email openapi_types.Email `json:"email"`
			Id    openapi_types.UUID  `json:"id"`
		}{
			Id:    openapi_types.UUID(user.ID),
			Email: openapi_types.Email(user.Email),
		},
	})
}

func (h *AuthHandler) V1AuthLoginPost(c *gin.Context) {
	var req api.V1AuthLoginPostJSONRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.Error400Response{
			Error: err.Error(),
		})
		return
	}

	response, err := h.authService.Login(string(req.Email), req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, api.Error401Response{
			Error: "invalid email or password",
		})
		return
	}

	c.JSON(http.StatusOK, api.V1AuthLoginPost200Response{
		AccessToken:          response.AccessToken,
		AccessTokenExpiresAt: response.AccessTokenExpiresAt,
		RefreshToken:         response.RefreshToken,
		User: struct {
			Email openapi_types.Email `json:"email"`
			Id    openapi_types.UUID  `json:"id"`
		}{
			Id:    openapi_types.UUID(response.User.ID),
			Email: openapi_types.Email(response.User.Email),
		},
	})
}

func (h *AuthHandler) V1AuthRefreshPost(c *gin.Context) {
	var req api.V1AuthRefreshPostJSONRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.Error400Response{
			Error: err.Error(),
		})
		return
	}

	response, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, api.Error401Response{
			Error: "invalid or expired refresh token",
		})
		return
	}

	result := api.V1AuthRefreshPost200Response{
		AccessToken: response.AccessToken,
	}
	if response.RefreshToken != "" {
		result.RefreshToken = &response.RefreshToken
	}

	c.JSON(http.StatusOK, result)
}

func (h *AuthHandler) V1AuthChangePasswordPost(c *gin.Context) {
	// Get user from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, api.Error401Response{
			Error: "unauthorized",
		})
		return
	}

	userIDUUID, ok := userID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, api.Error400Response{
			Error: "invalid user id",
		})
		return
	}

	var req api.V1AuthChangePasswordPostJSONRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.Error400Response{
			Error: err.Error(),
		})
		return
	}

	if err := h.authService.ChangePassword(userIDUUID, req.OldPassword, req.NewPassword); err != nil {
		if err.Error() == "invalid old password" {
			c.JSON(http.StatusUnauthorized, api.Error401Response{
				Error: err.Error(),
			})
			return
		}
		c.JSON(http.StatusBadRequest, api.Error400Response{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, api.V1AuthChangePasswordPost200Response{
		Message: "Password changed successfully",
	})
}

func (h *AuthHandler) V1AuthMeGet(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, api.Error401Response{
			Error: "unauthorized",
		})
		return
	}
	email, exists := c.Get("email")
	if !exists {
		c.JSON(http.StatusUnauthorized, api.Error401Response{
			Error: "unauthorized",
		})
		return
	}
	c.JSON(http.StatusOK, api.V1AuthMeGet200Response{
		Id:    openapi_types.UUID(userID.(uuid.UUID)),
		Email: openapi_types.Email(email.(string)),
	})
}
