package handlers

import (
  "bytes"
  "context"
  "encoding/base64"
  "encoding/json"
  "errors"
  "fmt"
  "net/http"
  "net/url"
  "strings"

  "projectgob-backend/internal/config"
)

type MailMessage struct {
  To      string
  Subject string
  Text    string
  HTML    string
}

type Mailer struct {
  disable bool
  sender  string
  cfg     config.Config
}

func NewMailer(cfg config.Config) *Mailer {
  return &Mailer{disable: cfg.EmailDisable, sender: cfg.SenderEmail, cfg: cfg}
}

// Send sends email via Gmail API using a refresh token.
// If EMAIL_DISABLE=true it becomes a no-op.
func (m *Mailer) Send(ctx context.Context, msg MailMessage) error {
  if m.disable {
    return nil
  }
  if m.sender == "" || m.cfg.RefreshToken == "" || m.cfg.GoogleClientID == "" || m.cfg.GoogleClientSecret == "" {
    return fmt.Errorf("gmail is not configured")
  }

  accessToken, err := m.refreshAccessToken(ctx)
  if err != nil {
    return err
  }

  raw := buildRawEmail(m.sender, msg)
  encoded := base64.RawURLEncoding.EncodeToString([]byte(raw))

  payload := map[string]string{"raw": encoded}
  b, _ := json.Marshal(payload)

  req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", bytes.NewReader(b))
  req.Header.Set("Authorization", "Bearer "+accessToken)
  req.Header.Set("Content-Type", "application/json")

  resp, err := http.DefaultClient.Do(req)
  if err != nil {
    return err
  }
  defer resp.Body.Close()

  if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    return errors.New("gmail send failed")
  }
  return nil
}

func (m *Mailer) refreshAccessToken(ctx context.Context) (string, error) {
  form := url.Values{}
  form.Set("client_id", m.cfg.GoogleClientID)
  form.Set("client_secret", m.cfg.GoogleClientSecret)
  form.Set("refresh_token", m.cfg.RefreshToken)
  form.Set("grant_type", "refresh_token")

  req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
  req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

  resp, err := http.DefaultClient.Do(req)
  if err != nil {
    return "", err
  }
  defer resp.Body.Close()

  var out struct {
    AccessToken string `json:"access_token"`
    TokenType   string `json:"token_type"`
    ExpiresIn   int    `json:"expires_in"`
    Error       string `json:"error"`
    ErrorDesc   string `json:"error_description"`
  }
  if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
    return "", err
  }
  if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    if out.Error != "" {
      return "", fmt.Errorf("google token refresh failed: %s", out.Error)
    }
    return "", errors.New("google token refresh failed")
  }
  if strings.TrimSpace(out.AccessToken) == "" {
    return "", errors.New("google token refresh failed: no access_token")
  }
  return strings.TrimSpace(out.AccessToken), nil
}

func buildRawEmail(from string, msg MailMessage) string {
  boundary := "mixedboundary123456789"
  var b strings.Builder
  b.WriteString(fmt.Sprintf("From: %s\r\n", from))
  b.WriteString(fmt.Sprintf("To: %s\r\n", msg.To))
  b.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))
  b.WriteString("MIME-Version: 1.0\r\n")

  if msg.HTML != "" {
    b.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary))

    b.WriteString(fmt.Sprintf("--%s\r\n", boundary))
    b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
    b.WriteString(msg.Text + "\r\n")

    b.WriteString(fmt.Sprintf("--%s\r\n", boundary))
    b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
    b.WriteString(msg.HTML + "\r\n")

    b.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
    return b.String()
  }

  b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
  b.WriteString(msg.Text + "\r\n")
  return b.String()
}
