package repository

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type AuthRepository struct {
	DB *sql.DB
}

func New(db *sql.DB) (*AuthRepository, error) {
	userRepo := &AuthRepository{DB: db}
	if err := userRepo.CreateTable(); err != nil {
		return nil, fmt.Errorf("failed to create user table: %w", err)
	}
	return userRepo, nil
}

func (u *AuthRepository) CreateTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS refresh_tokens(
	    user_id UUID PRIMARY KEY,
	    refresh_token_hash TEXT NOT NULL,
	    expires_at TIMESTAMP NOT NULL,
	    user_agent TEXT NOT NULL,
	    ip TEXT NOT NULL
	    );
`
	_, err := u.DB.Exec(query)
	return err
}

func (u *AuthRepository) SaveRefreshToken(ctx context.Context, userId uuid.UUID, token string, expiresAt time.Duration, userAgent, ip string) error {
	const f = "repository.SaveRefreshToken"
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error in: %s: %w", f, err)
	}
	query := `
				INSERT INTO refresh_tokens (user_id, refresh_token_hash, expires_at, user_agent, ip)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (user_id) DO UPDATE
				SET refresh_token_hash = $2, expires_at = $3, user_agent = $4, ip = $5
				`

	_, err = u.DB.ExecContext(ctx, query, userId, string(hashedToken), time.Now().Add(expiresAt), userAgent, ip)

	if err != nil {
		return fmt.Errorf("failed to insert refresh token in file: %s: %w ", f, err)
	}

	return nil
}

func (u *AuthRepository) GetRefreshToken(ctx context.Context, userId uuid.UUID) (tokenHash, userAgent, ip string, expiresAt time.Time, errReturn error) {
	const f = "repository.GetRefreshToken"
	query := ` SELECT refresh_token_hash, user_agent, ip, expires_at FROM refresh_tokens WHERE user_id = $1
	`
	rw := u.DB.QueryRowContext(ctx, query, userId)
	err := rw.Scan(&tokenHash, &userAgent, &ip, &expiresAt)
	if err != nil {
		errReturn = fmt.Errorf("failed to get refresh token: %s: %w", f, err)
	}
	return
}

func (u *AuthRepository) DeleteToken(ctx context.Context, userId uuid.UUID) error {
	const f = "repository.DeleteToken"
	query := `DELETE FROM refresh_tokens WHERE user_id = $1`
	_, err := u.DB.ExecContext(ctx, query, userId)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %s: %w", f, err)
	}
	return nil
}
