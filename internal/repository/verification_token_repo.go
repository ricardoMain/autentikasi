package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"autentikasi/internal/models"
	generated "autentikasi/prisma/generated"
)

type VerificationTokenRepository struct {
	prisma *generated.Client
}

func NewVerificationTokenRepository(prisma *generated.Client) *VerificationTokenRepository {
	return &VerificationTokenRepository{prisma: prisma}
}

func (r *VerificationTokenRepository) Create(ctx context.Context, userID uuid.UUID, token, purpose string, expiresAt time.Time) (*models.VerificationToken, error) {
	id := uuid.New()
	created, err := r.prisma.WithContext(ctx).VerificationToken().CreateOne().
		SetId(id.String()).
		SetUserId(userID.String()).
		SetToken(token).
		SetPurpose(purpose).
		SetExpiresAt(expiresAt).
		Exec()
	if err != nil {
		return nil, err
	}

	return &models.VerificationToken{
		ID:        uuid.MustParse(created.Id),
		UserID:    uuid.MustParse(created.UserId),
		Token:     created.Token,
		Purpose:   created.Purpose,
		ExpiresAt: created.ExpiresAt,
		CreatedAt: created.CreatedAt,
	}, nil
}

func (r *VerificationTokenRepository) FindByToken(ctx context.Context, token string) (*models.VerificationToken, error) {
	results, err := r.prisma.WithContext(ctx).VerificationToken().Where(map[string]interface{}{
		"token": token,
	}).FindMany()
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, sql.ErrNoRows
	}

	vt := &results[0]
	return &models.VerificationToken{
		ID:        uuid.MustParse(vt.Id),
		UserID:    uuid.MustParse(vt.UserId),
		Token:     vt.Token,
		Purpose:   vt.Purpose,
		ExpiresAt: vt.ExpiresAt,
		CreatedAt: vt.CreatedAt,
	}, nil
}

func (r *VerificationTokenRepository) DeleteByToken(ctx context.Context, token string) error {
	_, err := r.prisma.WithContext(ctx).VerificationToken().Delete(map[string]interface{}{
		"token": token,
	})
	return err
}
