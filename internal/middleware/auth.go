package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	jwtMy "github.com/romapopov1212/auth-test/internal/lib/jwt"
	"github.com/romapopov1212/auth-test/internal/repository"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

type Authorization struct {
	skipper   func(*gin.Context) bool
	logger    *zap.Logger
	authRepo  *repository.AuthRepository
	jwtSecret string
}

func NewAuthorizeMiddleware(logger *zap.Logger, skipper func(*gin.Context) bool, authRepository *repository.AuthRepository, jwtSecret string) *Authorization {
	return &Authorization{
		logger:    logger,
		skipper:   skipper,
		authRepo:  authRepository,
		jwtSecret: jwtSecret,
	}
}

func (auth *Authorization) Authorize() gin.HandlerFunc {
	return func(c *gin.Context) {
		if auth.skipper(c) {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		authHeaderParts := strings.Split(authHeader, " ")
		if len(authHeaderParts) != 2 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		claims, err := jwtMy.ValidateToken(authHeaderParts[1], auth.jwtSecret)

		if err != nil {
			auth.logger.Error(
				"Invalid token",
				zap.String("token", authHeaderParts[1]),
				zap.String("client_ip", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")),
				zap.Error(err),
			)
			auth.logger.Warn("middleware abort: invalid token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		c.Set("jwtClaims", claims)

		userId, err := uuid.Parse(claims["uid"].(string))
		if err != nil {
			return
		}

		_, _, _, _, err = auth.authRepo.GetRefreshToken(c.Request.Context(), userId)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		c.Next()
	}
}
