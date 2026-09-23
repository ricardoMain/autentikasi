package services

import (
	"fmt"
	"log/slog"
	"net/smtp"

	"autentikasi/internal/config"
)

type EmailService struct {
	cfg *config.Config
}

func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{cfg: cfg}
}

// Send delivers a plain-text email over SMTP. If SMTP isn't configured
// (local/dev), it's a no-op so registration/reset flows don't fail.
func (s *EmailService) Send(to, subject, body string) error {
	if s.cfg.SMTPHost == "" {
		slog.Info("SMTP not configured, logging email instead", "to", to, "subject", subject, "body", body)
		return nil
	}

	addr := fmt.Sprintf("%s:%s", s.cfg.SMTPHost, s.cfg.SMTPPort)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n", s.cfg.SMTPFrom, to, subject, body)

	var auth smtp.Auth
	if s.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	}

	return smtp.SendMail(addr, auth, s.cfg.SMTPFrom, []string{to}, []byte(msg))
}
