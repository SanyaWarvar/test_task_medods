package repository

import (
	"fmt"
	"time"

	"github.com/SanyaWarvar/auth/pkg/models"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type AuthPostgres struct {
	db *sqlx.DB
}

func NewAuthPostgres(db *sqlx.DB) *AuthPostgres {
	return &AuthPostgres{db: db}
}

const (
	usersTable  = "public.users"
	tokensTable = "public.tokens"
)

func (r *AuthPostgres) CreateUser(user models.User) error {
	query := fmt.Sprintf(`INSERT INTO %s (id, email, ip) VALUES ($1, $2, $3)`, usersTable)
	_, err := r.db.Exec(query, user.Guid, user.Email, user.Ip)

	return err
}

func (r *AuthPostgres) SaveToken(token string, user_id uuid.UUID, expDate time.Time) (int, error) {
	var id int
	query := fmt.Sprintf(`INSERT INTO %s (token, user_id, exp_date) VALUES ($1, $2, $3) RETURNING id`, tokensTable)
	err := r.db.Get(&id, query, token, user_id, expDate)
	return id, err
}

func (r *AuthPostgres) GetTokenById(id int) (models.RefreshToken, error) {
	var token models.RefreshToken

	query := fmt.Sprintf(`SELECT user_id, exp_date, token FROM %s WHERE id = $1`, tokensTable)
	err := r.db.Get(&token, query, id)

	return token, err
}

func (r *AuthPostgres) GetUserById(guid uuid.UUID) (models.User, error) {
	var user models.User

	query := fmt.Sprintf(`SELECT email, ip FROM %s WHERE id = $1`, usersTable)
	err := r.db.Get(&user, query, guid)

	return user, err
}

func (r *AuthPostgres) DeleteTokenByUserId(guid uuid.UUID) error {

	query := fmt.Sprintf(`DELETE FROM %s WHERE user_id = $1`, tokensTable)
	_, err := r.db.Exec(query, guid)

	return err
}
