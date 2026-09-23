package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"autentikasi/internal/models"
	generated "autentikasi/prisma/generated"
)

type OrganizationRepository struct {
	prisma *generated.Client
}

func NewOrganizationRepository(prisma *generated.Client) *OrganizationRepository {
	return &OrganizationRepository{prisma: prisma}
}

func (r *OrganizationRepository) Create(ctx context.Context, org *models.Organization) error {
	now := time.Now()
	org.ID = uuid.New()
	created, err := r.prisma.WithContext(ctx).Organization().CreateOne().
		SetId(org.ID.String()).
		SetName(org.Name).
		SetSlug(org.Slug).
		SetCreatedAt(now).
		SetUpdatedAt(now).
		Exec()
	if err != nil {
		return err
	}

	org.CreatedAt = created.CreatedAt
	org.UpdatedAt = created.UpdatedAt
	return nil
}

func (r *OrganizationRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	results, err := r.prisma.WithContext(ctx).Organization().Where(map[string]interface{}{
		"id": id.String(),
	}).FindMany()
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, sql.ErrNoRows
	}

	o := &results[0]
	return &models.Organization{
		ID:        uuid.MustParse(o.Id),
		Name:      o.Name,
		Slug:      o.Slug,
		CreatedAt: o.CreatedAt,
		UpdatedAt: o.UpdatedAt,
	}, nil
}
