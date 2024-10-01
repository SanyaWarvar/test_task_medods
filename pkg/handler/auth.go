package handler

import (
	"net/http"
	"time"

	"github.com/SanyaWarvar/auth/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func (h *Handler) auth(c *gin.Context) {
	if data := c.GetHeader("X-Forwarded-For"); data == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": "Missing header X-Forward-From"})
		return
	}

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
	err = h.services.IAuthorization.CreateUser(input)
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

	if data := c.GetHeader("X-Forwarded-For"); data == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": "Missing header X-Forward-From"})
		return
	}

	var input models.RefreshInput
	err := c.BindJSON(&input)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": err.Error()})
		return
	}

	decodedAccessClaims, err := h.services.IJwtManager.ParseClaims(input.AccessToken, &models.AccessTokenClaims{})
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
	result := h.services.IJwtManager.CompareTokens(hashedToken.Token, input.RefreshToken)
	if !result {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": "tokens dont match"})
		return
	}

	refreshToken, accessToken, err := h.GeneratePair(decodedAccessClaims.Guid, c.ClientIP())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"details": err.Error()})
		return
	}

	if c.ClientIP() != decodedAccessClaims.Ip {
		logrus.Infof("Change ip from %s to %s", decodedAccessClaims.Ip, c.ClientIP())
		go h.services.IEmailSmtp.Warning(decodedAccessClaims.Guid, c.ClientIP())
		// отправка сообщения очень долгая операция (около 3 секунд) поэтому запускаю в горутине, чтобы не ждать
	}

	c.JSON(http.StatusOK, map[string]string{
		"refresh_token": refreshToken,
		"access_token":  accessToken,
	})

}

func (h *Handler) GeneratePair(guid uuid.UUID, ip string) (string, string, error) {
	refreshToken, err := h.services.IJwtManager.GenerateRefreshToken(guid, ip)
	if err != nil {
		return "", "", err
	}
	refreshHash, err := h.services.IJwtManager.HashToken(refreshToken)
	if err != nil {
		return "", "", err
	}

	refreshId, err := h.services.IAuthorization.SaveToken(refreshHash, guid, time.Now().AddDate(0, 1, 0))
	if err != nil {
		return "", "", err
	}

	accessToken, err := h.services.IJwtManager.GenerateAccesstoken(guid, ip, refreshId)
	return refreshToken, accessToken, err
}
