package handlers

import (
  "crypto/rand"
  "bytes"
  "context"
  "encoding/base64"
  "encoding/hex"
  "encoding/json"
  "errors"
  "fmt"
  "mime"
  "mime/quotedprintable"
  "net/http"
  "net/url"
  "strings"
  "time"
  "unicode/utf8"

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
  // Outlook is picky. Include Date + Message-ID and use safe encodings.
  boundary := "alt_" + mailRandHex(12)
  msgID := makeMessageID(from)

  var b strings.Builder
  b.WriteString(fmt.Sprintf("From: %s\r\n", from))
  b.WriteString(fmt.Sprintf("To: %s\r\n", msg.To))
  b.WriteString(fmt.Sprintf("Subject: %s\r\n", encodeHeader(msg.Subject)))
  b.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
  b.WriteString(fmt.Sprintf("Message-ID: %s\r\n", msgID))
  b.WriteString("MIME-Version: 1.0\r\n")

  // Prefer TEXT only (best deliverability). HTML is optional.
  if strings.TrimSpace(msg.HTML) != "" {
    b.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary))

    // text/plain
    b.WriteString(fmt.Sprintf("--%s\r\n", boundary))
    b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
    b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
    b.WriteString(encodeQP(msg.Text))
    b.WriteString("\r\n")

    // text/html
    b.WriteString(fmt.Sprintf("--%s\r\n", boundary))
    b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
    b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
    b.WriteString(encodeQP(msg.HTML))
    b.WriteString("\r\n")

    b.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
    return b.String()
  }

  b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
  b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
  b.WriteString(encodeQP(msg.Text))
  b.WriteString("\r\n")
  return b.String()
}

func encodeHeader(s string) string {
  s = strings.TrimSpace(s)
  if s == "" {
    return ""
  }
  // If not valid UTF-8, fall back to raw.
  if !utf8.ValidString(s) {
    return s
  }
  // If all ASCII, no need for RFC 2047 encoding.
  ascii := true
  for _, r := range s {
    if r > 127 {
      ascii = false
      break
    }
  }
  if ascii {
    return s
  }
  return mime.QEncoding.Encode("utf-8", s)
}

func encodeQP(s string) string {
  var buf bytes.Buffer
  w := quotedprintable.NewWriter(&buf)
  _, _ = w.Write([]byte(s))
  _ = w.Close()
  return buf.String()
}

func makeMessageID(from string) string {
  // <random@domain>
  domain := "localhost"
  if at := strings.LastIndex(from, "@"); at >= 0 && at+1 < len(from) {
    d := strings.TrimSpace(from[at+1:])
    d = strings.Trim(d, ">")
    d = strings.Trim(d, "<")
    if d != "" {
      domain = d
    }
  }
  return "<" + mailRandHex(16) + "@" + domain + ">"
}

func mailRandHex(nBytes int) string {
  b := make([]byte, nBytes)
  _, _ = rand.Read(b)
  return hex.EncodeToString(b)
}
