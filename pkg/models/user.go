package models

import "github.com/google/uuid"

type User struct {
	Guid  uuid.UUID `json:"guid" db:"id"`
	Ip    string    `json:"ip" db:"ip"`
	Email string    `json:"email" db:"email" binding:"required"`
}
