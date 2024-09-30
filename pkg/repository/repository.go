package repository

import (
	"time"

	"github.com/SanyaWarvar/auth/pkg/models"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type Authorizer interface {
	CreateUser(user models.User) error
	SaveToken(token string, user_id uuid.UUID, expDate time.Time) (int, error)
	GetTokenById(id int) (models.RefreshToken, error)
}

type Repository struct {
	Authorizer
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{
		Authorizer: NewAuthPostgres(db),
	}
}
