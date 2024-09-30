package service

import (
	"time"

	"github.com/SanyaWarvar/auth/pkg/models"
	"github.com/SanyaWarvar/auth/pkg/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Authorization interface {
	CreateUser(user models.User) error
	SaveToken(token string, user_id uuid.UUID, expDate time.Time) (int, error)
	GetTokenById(id int) (models.RefreshToken, error)
}

type JwtManager interface {
	GenerateRefreshToken(guid uuid.UUID, ip string) (string, error)
	GenerateAccesstoken(guid uuid.UUID, ip string, id int) (string, error)
	ParseClaims(token string, claimsType jwt.Claims) (*models.AccessTokenClaims, error)
	CompareTokens(hashedToken, token string) bool
	HashToken(token string) (string, error)
}

type Service struct {
	Authorization
	JwtManager
}

func NewService(repos *repository.Repository, jwtConfig *Config) *Service {
	return &Service{
		Authorization: NewAuthService(repos.Authorizer),
		JwtManager:    NewJwtManager(jwtConfig),
	}
}
