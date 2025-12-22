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
	de := json.NewDecoder(r.Body)
	de.DisallowUnknownFields()
	return de.Decode(out)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]any{"error": msg})
}

func (h *Handler) writeErrFrom(w http.ResponseWriter, err error) {
	var pe *pureapi.Error
	if errors.As(err, &pe) {
		// Node/Docker style:
		// { error: "..." }
		msg := pe.Message
		details := extractPureDetails(pe.Detail)
		resp := map[string]any{"error": msg}
		if details != "" {
			resp["details"] = details
		}
		WriteJSON(w, pe.Status, resp)
		return
	}
	WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "Internal error"})
}

func extractPureDetails(detail any) string {
	m, ok := detail.(map[string]any)
	if !ok {
		return ""
	}
	errObj, ok := m["error"].(map[string]any)
	if !ok {
		return ""
	}
	if d, _ := errObj["details"].(string); d != "" {
		return d
	}
	return ""
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
