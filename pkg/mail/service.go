package mail

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// headerSafe strips CR/LF so a value can't inject extra SMTP/MIME headers.
func headerSafe(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

type Service struct {
	config Config
	auth   smtp.Auth
}

// NewService creates a new mail service with the given config.
func NewService(cfg Config) *Service {
	// If config is invalid, we might fallback to mock or just log error.
	// For now, we assume caller validates or we run in "Day 0 Mock" if empty.
	if err := cfg.Validate(); err != nil {
		log.Warn().Err(err).Msg("Invalid Mail Config. Mail service in MOCK mode.")
		return &Service{}
	}

	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	return &Service{
		config: cfg,
		auth:   auth,
	}
}

// SendInvitation sends an onboarding email with HTML template and Retry logic.
func (s *Service) SendInvitation(toEmail, inviteLink, orgName string) error {
	// 1. Mock Mode Check
	if s.config.SMTPHost == "" {
		log.Info().Str("to", toEmail).Str("link", inviteLink).Msg("📧 [MOCK] SENDING INVITATION 📧")
		return nil
	}

	// 2. Prepare Email Content
	toEmail = headerSafe(toEmail)
	from := headerSafe(s.config.From)
	subject := headerSafe(fmt.Sprintf("Welcome to ClearGate - %s Activation", orgName))
	body, err := s.buildEmailBody(orgName, inviteLink)
	if err != nil {
		return err
	}

	msg := []byte("To: " + toEmail + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"\r\n" +
		body)

	// 3. Send with Retry (3 attempts)
	addr := fmt.Sprintf("%s:%s", s.config.SMTPHost, s.config.SMTPPort)
	var sendErr error

	for i := 0; i < 3; i++ {
		// Use TLS if port 465, otherwise STARTTLS on 587 usually handled by Dial/StartTLS (net/smtp SendMail does STARTTLS automatically for us)
		// NOTE: net/smtp.SendMail enforces STARTTLS if available.
		// For pure SSL/TLS on 465, we need custom implementation, but standard 587 is safer default expectation.
		// We'll trust standard SendMail for now.

		sendErr = smtp.SendMail(addr, s.auth, s.config.From, []string{toEmail}, msg)
		if sendErr == nil {
			log.Info().Str("to", toEmail).Msg("Email sent successfully")
			return nil
		}

		log.Warn().Err(sendErr).Int("attempt", i+1).Msg("Failed to send email. Retrying...")
		time.Sleep(2 * time.Second)
	}

	log.Error().Err(sendErr).Msg("Failed to send email after 3 attempts")
	return sendErr
}

func (s *Service) buildEmailBody(orgName, link string) (string, error) {
	const tpl = `
<!DOCTYPE html>
<html>
<head>
<style>
	body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #e2e8f0; padding: 40px; }
	.container { max-width: 600px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5); }
	.header { text-align: center; margin-bottom: 32px; border-bottom: 1px solid #334155; padding-bottom: 24px; }
	.logo { font-size: 24px; font-weight: bold; color: #60a5fa; letter-spacing: -0.5px; }
	.content { line-height: 1.6; margin-bottom: 32px; }
	.btn { display: inline-block; background-color: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: 500; transition: background 0.2s; }
	.btn:hover { background-color: #2563eb; }
	.footer { text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #334155; padding-top: 24px; }
</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<div class="logo">ClearGate Security</div>
		</div>
		<div class="content">
			<h2 style="color: #f8fafc; margin-top: 0;">Welcome, {{.OrgName}} Admin!</h2>
			<p>Your secure Organization environment has been provisioned.</p>
			<p>ClearGate provides enterprise-grade protection for your GenAI usage, including PII Redaction, Prompt Injection Defense, and Audit Logging.</p>
			<p>Click the button below to activate your account and configure your security policies.</p>
			<div style="text-align: center; margin: 32px 0;">
				<a href="{{.Link}}" class="btn">Activate Secure Access</a>
			</div>
			<p style="font-size: 14px; opacity: 0.8;">Or copy this link: <br><a href="{{.Link}}" style="color: #60a5fa;">{{.Link}}</a></p>
		</div>
		<div class="footer">
			&copy; 2026 ClearGate Security Inc. <br>
			Protected by Vector Guard Technology.
		</div>
	</div>
</body>
</html>
`
	t, err := template.New("email").Parse(tpl)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, map[string]string{"OrgName": orgName, "Link": link}); err != nil {
		return "", err
	}
	return buf.String(), nil
}
