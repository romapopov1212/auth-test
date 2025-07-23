package main

import (
	"flag"
	"github.com/gin-gonic/gin"
	_ "github.com/romapopov1212/auth-test/docs"
	"github.com/romapopov1212/auth-test/internal/config"
	db2 "github.com/romapopov1212/auth-test/internal/db"
	"github.com/romapopov1212/auth-test/internal/handler"
	middleware2 "github.com/romapopov1212/auth-test/internal/middleware"
	"github.com/romapopov1212/auth-test/internal/repository"
	"github.com/romapopov1212/auth-test/internal/service"
	"go.uber.org/zap"
	"log"
	"strings"
)

// @title Auth Test API
// @version 1.0
// @description API для аутентификации и управления токенами
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token
func main() {
	configPath := flag.String("config", "./config", "path to the config file")
	flag.Parse()

	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("error init logger: %v", err)
	}

	logger.Info("starting app")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("error loading config")
	}

	db, _, err := db2.NewDatabaseConnection(cfg.Database)
	if err != nil {
		log.Fatalf("error init database connection: %v", err)
	}

	userRepo, err := repository.New(db)
	if err != nil {
		log.Fatalf("error to create table:%v", err)
	}

	authService := service.NewUserService(*userRepo, logger, cfg.Url, cfg.SecretKey)

	middleware := middleware2.NewAuthorizeMiddleware(logger, shouldSkipAuthMiddleware, userRepo, cfg.SecretKey)
	router := gin.Default()
	router.Use(middleware.Authorize())

	cntrl := handler.RegisterRoutes(authService, router, logger, middleware)
	_ = cntrl
	serverAddr := cfg.Address
	logger.Info("starting server", zap.String("address", serverAddr))
	if err := router.Run(serverAddr); err != nil {
		logger.Fatal("failed to start server", zap.Error(err))
	}
}

func shouldSkipAuthMiddleware(c *gin.Context) bool {
	if strings.HasSuffix(c.Request.URL.Path, "/tokens") || strings.HasSuffix(c.Request.URL.Path, "/refresh") ||
		strings.HasPrefix(c.Request.URL.Path, "/swagger/") ||
		c.Request.URL.Path == "/favicon.ico" {
		return true
	}
	return false
}
