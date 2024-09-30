package service

import (
	"time"

	"github.com/SanyaWarvar/auth/pkg/models"
	"github.com/SanyaWarvar/auth/pkg/repository"
	"github.com/google/uuid"
)

type AuthService struct {
	repo repository.Authorizer
}

func NewAuthService(repo repository.Authorizer) *AuthService {
	return &AuthService{repo: repo}
}

func (s *AuthService) CreateUser(user models.User) error {
	return s.repo.CreateUser(user)
}

func (s *AuthService) SaveToken(token string, user_id uuid.UUID, expDate time.Time) (int, error) {
	return s.repo.SaveToken(token, user_id, expDate)
}

func (s *AuthService) GetTokenById(id int) (models.RefreshToken, error) {
	return s.repo.GetTokenById(id)
}
