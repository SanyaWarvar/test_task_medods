package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/SanyaWarvar/auth/pkg/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Key       string
	AccessTTL time.Duration
	Method    jwt.SigningMethod
}

type Manager struct {
	config *Config
}

func NewJwtManager(config *Config) *Manager {
	return &Manager{
		config: config,
	}
}

func (m *Manager) GenerateRefreshToken(guid uuid.UUID, ip string) (string, error) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}

	token := base64.URLEncoding.EncodeToString(tokenBytes)

	return token, nil
}

func (m *Manager) GenerateAccesstoken(guid uuid.UUID, ip string, id int) (string, error) {
	jwtClaims := models.AccessTokenClaims{
		Guid:      guid,
		Ip:        ip,
		RefreshId: id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.config.AccessTTL)),
		},
	}

	token := jwt.NewWithClaims(
		m.config.Method,
		jwtClaims,
	)

	return token.SignedString([]byte(m.config.Key))
}

func (m *Manager) ParseClaims(token string, claimsType jwt.Claims) (*models.AccessTokenClaims, error) {
	parsedToken, err := jwt.ParseWithClaims(token, claimsType, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}

		return []byte(m.config.Key), nil
	})
	if err != nil {
		return nil, err
	}

	claims, _ := parsedToken.Claims.(*models.AccessTokenClaims)

	return claims, err
}

func (m *Manager) HashToken(token string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return string(hashedToken), err
}

func (m *Manager) CompareTokens(hashedToken, token string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(token)) == nil
}

