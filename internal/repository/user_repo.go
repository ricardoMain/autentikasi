package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"autentikasi/internal/models"
	generated "autentikasi/prisma/generated"
)

type UserRepository struct {
	prisma *generated.Client
}

func NewUserRepository(prisma *generated.Client) *UserRepository {
	return &UserRepository{prisma: prisma}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	now := time.Now()
	user.ID = uuid.New()
	created, err := r.prisma.WithContext(ctx).User().CreateOne().
		SetId(user.ID.String()).
		SetEmail(user.Email).
		SetPassword(strPtr(user.Password)).
		SetName(strPtr(user.Name)).
		SetAvatarUrl(strPtr(user.AvatarURL)).
		SetRole(user.Role).
		SetProvider(user.Provider).
		SetProviderId(strPtr(user.ProviderID)).
		SetCreatedAt(now).
		SetUpdatedAt(now).
		Exec()
	if err != nil {
		return err
	}

	user.CreatedAt = created.CreatedAt
	user.UpdatedAt = created.UpdatedAt
	return nil
}

func (r *UserRepository) findBy(ctx context.Context, where map[string]interface{}) (*models.User, error) {
	results, err := r.prisma.WithContext(ctx).User().Where(where).FindMany()
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, sql.ErrNoRows
	}
	return toModelUser(&results[0]), nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	return r.findBy(ctx, map[string]interface{}{"email": email})
}

func (r *UserRepository) FindByProvider(ctx context.Context, provider, providerID string) (*models.User, error) {
	return r.findBy(ctx, map[string]interface{}{"provider": provider, "providerId": providerID})
}

func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return r.findBy(ctx, map[string]interface{}{"id": id.String()})
}

func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	_, err := r.prisma.WithContext(ctx).User().Where(map[string]interface{}{
		"id": user.ID.String(),
	}).UpdateOne().
		SetName(strPtr(user.Name)).
		SetAvatarUrl(strPtr(user.AvatarURL)).
		Exec()
	return err
}

func toModelUser(u *generated.User) *models.User {
	return &models.User{
		ID:         uuid.MustParse(u.Id),
		Email:      u.Email,
		Password:   strVal(u.Password),
		Name:       strVal(u.Name),
		AvatarURL:  strVal(u.AvatarUrl),
		Role:       u.Role,
		Provider:   u.Provider,
		ProviderID: strVal(u.ProviderId),
		CreatedAt:  u.CreatedAt,
		UpdatedAt:  u.UpdatedAt,
	}
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
