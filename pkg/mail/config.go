package mail

import (
	"fmt"
)

type Config struct {
	SMTPHost string
	SMTPPort string
	SMTPUser string
	SMTPPass string
	From     string
}

func (c *Config) Validate() error {
	if c.SMTPHost == "" || c.SMTPPort == "" {
		return fmt.Errorf("missing SMTP host or port")
	}
	if c.SMTPUser == "" || c.SMTPPass == "" {
		return fmt.Errorf("missing SMTP credentials")
	}
	if c.From == "" {
		return fmt.Errorf("missing FROM email address")
	}
	return nil
}
