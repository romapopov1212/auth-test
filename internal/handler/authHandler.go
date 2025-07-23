package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net/http"
)

//type AuthHandler struct {
//	authService *service.AuthService
//}
//
//func NewAuthHandler(authService *service.AuthService) *AuthHandler {
//	return &AuthHandler{authService: authService}
//}

type (
	// TokenResponse represents token pair response
	// @name tokenResponse
	TokenResponse struct {
		AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
		RefreshToken string `json:"refresh_token" example:"f7a9e8bb-dc1e-4fdb-9a92-9a8b5d8e7f6c"`
	}

	// RefreshRequest represents refresh token request
	// @name refreshRequest
	RefreshRequest struct {
		AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
		RefreshToken string `json:"refresh_token" example:"f7a9e8bb-dc1e-4fdb-9a92-9a8b5d8e7f6c"`
	}

	// ErrorResponse represents error response
	// @name ErrorResponse
	ErrorResponse struct {
		Error string `json:"error" example:"error message"`
	}

	// MessageResponse represents message response
	// @name MessageResponse
	MessageResponse struct {
		Message string `json:"message" example:"success message"`
	}
)

// GetAccessAndRefreshTokens godoc
// @Summary Получить новую пару токенов
// @Description Генерирует access и refresh токены для пользователя
// @Tags auth
// @Accept json
// @Produce json
// @Param user_id query string true "User UUID"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /tokens [get]
func (h *Controller) GetAccessAndRefreshTokens(c *gin.Context) {
	userIdFromQuery := c.Query("user_id")
	if userIdFromQuery == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}
	userId, err := uuid.Parse(userIdFromQuery)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}
	userAgent := c.Request.UserAgent()
	ip := c.ClientIP()

	accessToken, refreshToken, err := h.authService.GetAccessAndRefreshToken(c.Request.Context(), userId, userAgent, ip)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		accessToken,
		refreshToken,
	})
}

// RefreshTokens godoc
// @Summary Обновить пару токенов
// @Description Генерирует новую пару токенов по refresh токену
// @Tags auth
// @Accept json
// @Produce json
// @Param input body RefreshRequest true "Токены"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /tokens/refresh [post]
func (h *Controller) RefreshTokens(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	userAgent := c.Request.UserAgent()
	ip := c.ClientIP()

	newAccess, newRefresh, err := h.authService.RefreshTokens(c.Request.Context(), req.AccessToken, req.RefreshToken, userAgent, ip)
	if err != nil {
		h.logger.Info("RefreshTokens handler called")
		h.logger.Warn("failed to refresh token", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to refresh"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	})
}

// GetCurrentUser godoc
// @Summary Получить текущего пользователя
// @Description Возвращает GUID аутентифицированного пользователя
// @Tags users
// @Security BearerAuth
// @Produce json
// @Failure 401 {object} ErrorResponse
// @Router /me [get]
func (h *Controller) GetCurrentUser(c *gin.Context) {
	claims, ok := c.Get("jwtClaims")
	if !ok {
		h.logger.Error("jwt claims not found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userClaims := claims.(jwt.MapClaims)
	userId := userClaims["uid"].(string)

	c.JSON(http.StatusOK, gin.H{"user_id": userId})
}

// Logout godoc
// @Summary Выход из системы
// @Description Удаляет refresh токен пользователя
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} MessageResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /logout [post]
func (h *Controller) Logout(c *gin.Context) {
	claims, ok := c.Get("jwtClaims")
	if !ok {
		h.logger.Error("jwt claims not found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userId, err := uuid.Parse(claims.(jwt.MapClaims)["uid"].(string))
	if err != nil {
		h.logger.Error("invalid user id")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	if err := h.authService.Logout(c.Request.Context(), userId); err != nil {
		h.logger.Error("failed to delete refresh token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}
