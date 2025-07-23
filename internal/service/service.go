package service

import (
	//"bytes"
	"context"
	//"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/romapopov1212/auth-test/internal/lib/jwt"
	"github.com/romapopov1212/auth-test/internal/repository"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	//"net/http"
	"time"
)

const (
	durationAccess  = time.Minute * 15
	durationRefresh = time.Hour * 6
)

type AuthService struct {
	authRepo   repository.AuthRepository
	logger     *zap.Logger
	webHookUrl string
	jwtSecret  string
}

func NewUserService(
	authRepo repository.AuthRepository,
	logger *zap.Logger,
	webHookUrl string,
	jwtSecret string,
) AuthService {
	return AuthService{authRepo: authRepo, logger: logger, webHookUrl: webHookUrl, jwtSecret: jwtSecret}
}

func (s *AuthService) GetAccessAndRefreshToken(ctx context.Context, userId uuid.UUID, userAgent, ip string) (string, string, error) {
	const op = "service.GetAccessAndRefreshToken"
	accessToken, err := jwt.NewToken(userId, durationAccess, s.jwtSecret)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	refreshToken, err := jwt.NewRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	err = s.authRepo.SaveRefreshToken(ctx, userId, refreshToken, durationRefresh, userAgent, ip)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) RefreshTokens(ctx context.Context, accessToken, refreshToken string, userAgentCurrent string, currentIp string) (string, string, error) {
	const op = "service.RefreshTokens"

	claims, err := jwt.ValidateToken(accessToken, s.jwtSecret)
	if err != nil {
		return "", "", fmt.Errorf("error to validate token in: %s, %w", op, err)
	}

	uidString, ok := claims["uid"].(string)
	if !ok {
		return "", "", fmt.Errorf("uid not found: %s", op)
	}

	userId, err := uuid.Parse(uidString)
	if err != nil {
		return "", "", fmt.Errorf("invalid user id in token: %s: %w", op, err)
	}

	dbTokenHash, dbUserAgent, _, expiresAt, err := s.authRepo.GetRefreshToken(ctx, userId)
	if err != nil {
		return "", "", fmt.Errorf("%s: failed to get refresh token: %w", op, err)
	}

	if time.Now().After(expiresAt) {
		_ = s.authRepo.DeleteToken(ctx, userId)
		return "", "", fmt.Errorf("%s: refresh token expired", op)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(dbTokenHash), []byte(refreshToken)); err != nil {
		_ = s.authRepo.DeleteToken(ctx, userId)
		return "", "", fmt.Errorf("%s: invalid refresh token", op)
	}

	if dbUserAgent != userAgentCurrent {
		_ = s.authRepo.DeleteToken(ctx, userId)
		return "", "", fmt.Errorf("%s: user agent mismatch", op)
	}

	return s.GetAccessAndRefreshToken(ctx, userId, userAgentCurrent, currentIp)
}

func (s *AuthService) Logout(ctx context.Context, userId uuid.UUID) error {
	return s.authRepo.DeleteToken(ctx, userId)
}
