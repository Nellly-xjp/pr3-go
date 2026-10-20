package email

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/smtp"
	"time"
)

type EmailService struct {
	Host     string // e.g., "smtp.ukr.net" або "smtp.gmail.com"
	Port     string // "465" (для SSL/TLS) або "587" (для STARTTLS)
	Username string // Ваша поштова адреса
	Password string // Пароль додатка (App Password)
}

func NewEmailService(host, port, username, password string) *EmailService {
	return &EmailService{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
	}
}

func (e *EmailService) SendMIMEAlert(to string, incidentMsg string, clientCN string, certSerial string) error {
	boundary := "---=_NextPart_Boundary_ZeroTrust_Gateway_123456789"
	nowStr := time.Now().Format(time.RFC1123Z)

	var msgBuf bytes.Buffer

	// 1. Стандартні MIME заголовки
	msgBuf.WriteString(fmt.Sprintf("From: %s\r\n", e.Username))
	msgBuf.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msgBuf.WriteString(fmt.Sprintf("Subject: [КРИТИЧНЕ СПОВІЩЕННЯ] Аварія від %s\r\n", clientCN))
	msgBuf.WriteString("MIME-Version: 1.0\r\n")
	msgBuf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", boundary))

	// 2. Секція HTML
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><style>
	body { font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }
	.card { background: white; padding: 20px; border-radius: 8px; border-left: 6px solid #d9534f; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
	.alert-title { color: #d9534f; font-size: 20px; font-weight: bold; margin-bottom: 10px; }
	table { width: 100%%; border-collapse: collapse; margin-top: 15px; }
	th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
	th { background-color: #f8f9fa; }
</style></head>
<body>
	<div class="card">
		<div class="alert-title">🚨 УВАГА! РЕЄСТРАЦІЯ КРИТИЧНОГО ІНЦИДЕНТУ</div>
		<p>Шлюзом mTLS було зафіксоване термінове сповіщення про аварію.</p>
		<table>
			<tr><th>Джерело (Common Name):</th><td>%s</td></tr>
			<tr><th>Серійний номер сертифіката:</th><td>%s</td></tr>
			<tr><th>Час реєстрації:</th><td>%s</td></tr>
			<tr><th>Деталі інциденту:</th><td><strong>%s</strong></td></tr>
		</table>
	</div>
</body>
</html>`, clientCN, certSerial, nowStr, incidentMsg)

	msgBuf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msgBuf.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msgBuf.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	msgBuf.WriteString(htmlBody)
	msgBuf.WriteString("\r\n\r\n")

	// 3. Секція Вкладення Base64 (incident_report.log)
	logContent := fmt.Sprintf("=== AUDIT LOG RECORD ===\nTimestamp: %s\nDevice CN: %s\nCertificate Serial: %s\nPayload: %s\nVerification Status: mTLS VERIFIED SUCCESS\n",
		nowStr, clientCN, certSerial, incidentMsg)

	encodedLog := base64.StdEncoding.EncodeToString([]byte(logContent))

	msgBuf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msgBuf.WriteString("Content-Type: text/plain; name=\"incident_report.log\"\r\n")
	msgBuf.WriteString("Content-Transfer-Encoding: base64\r\n")
	msgBuf.WriteString("Content-Disposition: attachment; filename=\"incident_report.log\"\r\n\r\n")

	for i := 0; i < len(encodedLog); i += 76 {
		end := i + 76
		if end > len(encodedLog) {
			end = len(encodedLog)
		}
		msgBuf.WriteString(encodedLog[i:end] + "\r\n")
	}
	msgBuf.WriteString("\r\n")
	msgBuf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	// 4. Авторизація та відправка пошти
	auth := smtp.PlainAuth("", e.Username, e.Password, e.Host)
	addr := fmt.Sprintf("%s:%s", e.Host, e.Port)

	if e.Port == "465" {
		return sendMailTLS(addr, e.Host, auth, e.Username, []string{to}, msgBuf.Bytes())
	}

	return smtp.SendMail(addr, auth, e.Username, []string{to}, msgBuf.Bytes())
}

func sendMailTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return fmt.Errorf("помилка TLS з'єднання з SMTP: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("помилка створення SMTP клієнта: %w", err)
	}
	defer client.Quit()

	if auth != nil {
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("помилка SMTP авторизації: %w", err)
		}
	}

	if err = client.Mail(from); err != nil {
		return err
	}

	for _, addr := range to {
		if err = client.Rcpt(addr); err != nil {
			return err
		}
	}

	w, err := client.Data()
	if err != nil {
		return err
	}

	_, err = w.Write(msg)
	if err != nil {
		return err
	}

	return w.Close()
}
