package services

import (
	"fmt"
	"net/smtp"

	"boilerplate/internal/config"

	"github.com/rs/zerolog/log"
)

type EmailService interface {
	SendRegistrationEmail(email, password string) error
}

type emailService struct {
	config *config.Config
}

func NewEmailService(cfg *config.Config) EmailService {
	return &emailService{config: cfg}
}

func (s *emailService) SendRegistrationEmail(email, password string) error {
	if !s.config.EmailEnabled {
		log.Info().Str("email", email).Msg("Email disabled, skipping registration email")
		return nil
	}

	// Email content
	subject := "Welcome! Your Account Has Been Created"
	body := fmt.Sprintf(`
Hello,

Your account has been successfully created!

Account Details:
- Email: %s
- Password: %s

Please keep your password secure and consider changing it after your first login.

Best regards,
%s
`, email, password, s.config.EmailFromName)

	// Build email message
	message := fmt.Sprintf("From: %s <%s>\r\n", s.config.EmailFromName, s.config.EmailFromAddress)
	message += fmt.Sprintf("To: %s\r\n", email)
	message += fmt.Sprintf("Subject: %s\r\n", subject)
	message += "MIME-Version: 1.0\r\n"
	message += "Content-Type: text/plain; charset=UTF-8\r\n"
	message += "\r\n"
	message += body

	// SMTP configuration
	addr := fmt.Sprintf("%s:%d", s.config.EmailSMTPHost, s.config.EmailSMTPPort)
	auth := smtp.PlainAuth("", s.config.EmailSMTPUsername, s.config.EmailSMTPPassword, s.config.EmailSMTPHost)

	// Send email
	err := smtp.SendMail(addr, auth, s.config.EmailFromAddress, []string{email}, []byte(message))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Info().Str("email", email).Msg("Registration email sent successfully")
	return nil
}

// MockEmailService for testing or when email is disabled
type MockEmailService struct{}

func NewMockEmailService() EmailService {
	return &MockEmailService{}
}

func (m *MockEmailService) SendRegistrationEmail(email, password string) error {
	log.Info().
		Str("email", email).
		Str("password", password).
		Msg("Mock: Registration email would be sent")
	return nil
}
