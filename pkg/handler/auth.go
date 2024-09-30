package handler

import (
	"net/http"
	"time"

	"github.com/SanyaWarvar/auth/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (h *Handler) auth(c *gin.Context) {
	var input models.User
	guidString := c.Params.ByName("guid")
	guid, err := uuid.Parse(guidString)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": err.Error()})
		return
	}
	err = c.BindJSON(&input)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": err.Error()})
		return
	}
	input.Guid = guid

	input.Ip = c.ClientIP() // нужен header "X-Forwarded-For"
	err = h.services.Authorization.CreateUser(input)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": err.Error()})
		return
	}

	refreshToken, accessToken, err := h.GeneratePair(input.Guid, input.Ip)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, map[string]string{
		"refresh_token": refreshToken,
		"access_token":  accessToken,
	})
}

func (h *Handler) refresh(c *gin.Context) {
	var input models.RefreshInput
	err := c.BindJSON(&input)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": err.Error()})
		return
	}

	decodedAccessClaims, err := h.services.JwtManager.ParseClaims(input.AccessToken, &models.AccessTokenClaims{})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": err.Error()})
		return
	}

	hashedToken, err := h.services.GetTokenById(decodedAccessClaims.RefreshId)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": err.Error()})
		return
	}

	if hashedToken.ExpDate.Before(time.Now()) || hashedToken.UserId != decodedAccessClaims.Guid {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": "invalid user id or token is exp"})
		return
	}
	result := h.services.JwtManager.CompareTokens(hashedToken.Token, input.RefreshToken)
	if !result {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": "tokens dont match"})
		return
	}

	refreshToken, accessToken, err := h.GeneratePair(decodedAccessClaims.Guid, decodedAccessClaims.Ip)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, map[string]string{
		"refresh_token": refreshToken,
		"access_token":  accessToken,
	})

}

func (h *Handler) GeneratePair(guid uuid.UUID, ip string) (string, string, error) {
	refreshToken, err := h.services.JwtManager.GenerateRefreshToken(guid, ip)
	if err != nil {
		return "", "", err
	}
	refreshHash, err := h.services.JwtManager.HashToken(refreshToken)
	if err != nil {
		return "", "", err
	}

	refreshId, err := h.services.Authorization.SaveToken(refreshHash, guid, time.Now().AddDate(0, 1, 0))
	if err != nil {
		return "", "", err
	}

	accessToken, err := h.services.JwtManager.GenerateAccesstoken(guid, ip, refreshId)
	return refreshToken, accessToken, err
}
