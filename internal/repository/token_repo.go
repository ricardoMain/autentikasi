package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"autentikasi/internal/models"
	generated "autentikasi/prisma/generated"
)

type TokenRepository struct {
	prisma *generated.Client
}

func NewTokenRepository(prisma *generated.Client) *TokenRepository {
	return &TokenRepository{prisma: prisma}
}

func (r *TokenRepository) Create(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*models.RefreshToken, error) {
	id := uuid.New()
	created, err := r.prisma.WithContext(ctx).RefreshToken().CreateOne().
		SetId(id.String()).
		SetUserId(userID.String()).
		SetToken(token).
		SetExpiresAt(expiresAt).
		Exec()
	if err != nil {
		return nil, err
	}

	return &models.RefreshToken{
		ID:        uuid.MustParse(created.Id),
		UserID:    uuid.MustParse(created.UserId),
		Token:     created.Token,
		ExpiresAt: created.ExpiresAt,
		CreatedAt: created.CreatedAt,
	}, nil
}

func (r *TokenRepository) FindByToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	results, err := r.prisma.WithContext(ctx).RefreshToken().Where(map[string]interface{}{
		"token": token,
	}).FindMany()
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, sql.ErrNoRows
	}

	rt := &results[0]
	return &models.RefreshToken{
		ID:        uuid.MustParse(rt.Id),
		UserID:    uuid.MustParse(rt.UserId),
		Token:     rt.Token,
		ExpiresAt: rt.ExpiresAt,
		CreatedAt: rt.CreatedAt,
	}, nil
}

func (r *TokenRepository) DeleteByToken(ctx context.Context, token string) error {
	_, err := r.prisma.WithContext(ctx).RefreshToken().Delete(map[string]interface{}{
		"token": token,
	})
	return err
}

func (r *TokenRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := r.prisma.WithContext(ctx).RefreshToken().Delete(map[string]interface{}{
		"userId": userID.String(),
	})
	return err
}
