package service

import (
	"fmt"
	"net/smtp"

	"github.com/SanyaWarvar/auth/pkg/repository"
	"github.com/google/uuid"
)

type EmailSettings struct {
	OwnerEmail    string
	OwnerPassword string
	Address       string
}

func NewEmailSettings(ownerEmail, ownerPassword, addr string) *EmailSettings {
	return &EmailSettings{
		OwnerEmail:    ownerEmail,
		OwnerPassword: ownerPassword,
		Address:       addr,
	}
}

type EmailSmtp struct {
	repo     repository.Authorizer
	settings *EmailSettings
}

func NewEmailSmtpService(repo repository.Authorizer, settings *EmailSettings) *EmailSmtp {
	return &EmailSmtp{repo: repo, settings: settings}
}

func (m *EmailSmtp) Warning(guid uuid.UUID, newIp string) error {
	user, err := m.repo.GetUserById(guid)
	if err != nil {
		return err
	}

	return m.SendMessage(user.Email, m.GenerateWarningMessage(newIp), fmt.Sprintf("New IP warning! New IP: %s", newIp))

}

func (m *EmailSmtp) GenerateWarningMessage(ip string) string {
	return fmt.Sprintf("Your ip address has been changed! New ip: %s.", ip)
}

func (m *EmailSmtp) SendMessage(email, messageText, title string) error {

	toEmail := email
	fromEmail := m.settings.OwnerEmail

	subject_body := fmt.Sprintf("Subject:%s\n\n %s", title, messageText)
	status := smtp.SendMail(
		"smtp.gmail.com:587",
		smtp.PlainAuth("", fromEmail, m.settings.OwnerPassword, "smtp.gmail.com"),
		fromEmail,
		[]string{toEmail},
		[]byte(subject_body),
	)
	fmt.Println(status)
	return status
}
