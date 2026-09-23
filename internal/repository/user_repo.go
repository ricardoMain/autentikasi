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
		SetEmailVerified(user.EmailVerified).
		SetTotpSecret(strPtr(user.TOTPSecret)).
		SetTotpEnabled(user.TOTPEnabled).
		SetOrganizationId(user.OrganizationID.String()).
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

// Update persists user's mutable fields. Uses the Where().Update(data) form
// directly because UserQuery.UpdateOne() drops the Where() filter, which
// makes the compiler reject the query for missing a WHERE clause.
func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	updated, err := r.prisma.WithContext(ctx).User().Where(map[string]interface{}{
		"id": user.ID.String(),
	}).Update(map[string]interface{}{
		"name":          strPtr(user.Name),
		"avatarUrl":     strPtr(user.AvatarURL),
		"password":      strPtr(user.Password),
		"emailVerified": user.EmailVerified,
		"totpSecret":    strPtr(user.TOTPSecret),
		"totpEnabled":   user.TOTPEnabled,
		"updatedAt":     time.Now(),
	})
	if err != nil {
		return err
	}
	user.UpdatedAt = updated.UpdatedAt
	return nil
}

func toModelUser(u *generated.User) *models.User {
	return &models.User{
		ID:             uuid.MustParse(u.Id),
		Email:          u.Email,
		Password:       strVal(u.Password),
		Name:           strVal(u.Name),
		AvatarURL:      strVal(u.AvatarUrl),
		Role:           u.Role,
		Provider:       u.Provider,
		ProviderID:     strVal(u.ProviderId),
		EmailVerified:  u.EmailVerified,
		TOTPSecret:     strVal(u.TotpSecret),
		TOTPEnabled:    u.TotpEnabled,
		OrganizationID: uuid.MustParse(u.OrganizationId),
		CreatedAt:      u.CreatedAt,
		UpdatedAt:      u.UpdatedAt,
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
