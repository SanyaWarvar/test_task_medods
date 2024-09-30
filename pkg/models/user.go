package models

import "github.com/google/uuid"

type User struct {
	Guid  uuid.UUID `json:"guid"`
	Ip    string    `json:"ip"`
	Email string    `json:"email" binding:"required"`
}
