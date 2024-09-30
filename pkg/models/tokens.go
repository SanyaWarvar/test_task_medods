package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type RefreshToken struct {
	Token   string    `db:"token"`
	UserId  uuid.UUID `db:"user_id"`
	ExpDate time.Time `db:"exp_date"`
}

type AccessTokenClaims struct {
	Guid      uuid.UUID `json:"guid"`
	Ip        string    `json:"ip"`
	RefreshId int       `json:"refreshId"`
	jwt.RegisteredClaims
}

type RefreshInput struct {
	AccessToken  string `json:"access_token" binding:"required"`
	RefreshToken string `json:"refresh_token" binding:"required"`
}
