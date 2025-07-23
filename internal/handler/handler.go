package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/romapopov1212/auth-test/internal/middleware"
	"github.com/romapopov1212/auth-test/internal/service"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
	_ "github.com/romapopov1212/auth-test/docs"
)

type Controller struct {
	authService    service.AuthService
	router         *gin.Engine
	logger         *zap.Logger
	authMiddleware *middleware.Authorization
}

func RegisterRoutes(authServ service.AuthService, router *gin.Engine, logger *zap.Logger, auth *middleware.Authorization) Controller {
	cntrl := Controller{
		authService:    authServ,
		router:         router,
		logger:         logger,
		authMiddleware: auth,
	}

	cntrl.router.GET("swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	cntrl.router.GET("/api/v1/tokens", cntrl.GetAccessAndRefreshTokens)
	cntrl.router.POST("/api/v1/tokens/refresh", cntrl.RefreshTokens)
	cntrl.router.GET("/api/v1/me", cntrl.GetCurrentUser)
	cntrl.router.POST("/api/v1/logout", cntrl.Logout)

	return cntrl
}
