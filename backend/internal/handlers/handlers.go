package handlers

import (
  "encoding/json"
  "errors"
  "net/http"
  "strings"

  "projectgob-backend/internal/config"
  "projectgob-backend/internal/pureapi"
)

type Handler struct {
  Cfg    config.Config
  Pure   *pureapi.Client
  Mail   *Mailer
  Google *GoogleOAuth
}

func New(cfg config.Config, p *pureapi.Client) *Handler {
  h := &Handler{Cfg: cfg, Pure: p}
  h.Mail = NewMailer(cfg)
  h.Google = NewGoogleOAuth(cfg)
  return h
}

// ---- small helpers ----

func WriteJSON(w http.ResponseWriter, status int, v any) {
  w.Header().Set("content-type", "application/json; charset=utf-8")
  w.WriteHeader(status)
  _ = json.NewEncoder(w).Encode(v)
}

func ReadJSON(r *http.Request, out any) error {
  dec := json.NewDecoder(r.Body)
  return dec.Decode(out)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, msg string) {
  WriteJSON(w, status, map[string]any{"error": msg})
}

func (h *Handler) writeErrFrom(w http.ResponseWriter, err error) {
  var pe *pureapi.Error
  if errors.As(err, &pe) {
    WriteJSON(w, pe.Status, map[string]any{
      "error":   true,
      "message": pe.Message,
      "status":  pe.Status,
    })
    return
  }
  WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": true, "message": "Internal error"})
}

func bearerToken(r *http.Request) string {
  v := r.Header.Get("Authorization")
  if v == "" {
    return ""
  }
  if strings.HasPrefix(strings.ToLower(v), "bearer ") {
    return strings.TrimSpace(v[7:])
  }
  return ""
}
