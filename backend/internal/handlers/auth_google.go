package handlers

import (
  "net/http"
  "net/url"
  "strings"
)

// GET /api/auth/google
func (h *Handler) AuthGoogleStart(w http.ResponseWriter, r *http.Request) {
  u, ok := h.Google.AuthURL("state")
  if !ok {
    h.writeError(w, http.StatusInternalServerError, "Google auth is not configured on server")
    return
  }
  http.Redirect(w, r, u, http.StatusFound)
}

// GET /api/auth/google/callback
func (h *Handler) AuthGoogleCallback(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  code := r.URL.Query().Get("code")
  if code == "" {
    http.Redirect(w, r, h.Cfg.FrontendURL+"/login?error=oauth_failed", http.StatusFound)
    return
  }

  info, err := h.Google.ExchangeWeb(ctx, code)
  if err != nil || info == nil || info.Email == "" {
    http.Redirect(w, r, h.Cfg.FrontendURL+"/login?error=oauth_failed", http.StatusFound)
    return
  }

  // Upsert oauth user in pure-api
  var out okData[userDTO]
  err = h.Pure.Post(ctx, "/api/internal/set-oauth-user", map[string]any{
    "email":      info.Email,
    "provider":   "google",
    "oauthId":    info.ID,        // ✅ แก้จาก Sub -> ID
    "pictureUrl": info.Picture,
    "name":       info.Name,
  }, &out)
  if err != nil || !out.Ok || out.Data == nil {
    http.Redirect(w, r, h.Cfg.FrontendURL+"/login?error=oauth_failed", http.StatusFound)
    return
  }

  token, err := h.signToken(out.Data.ID, out.Data.Role)
  if err != nil {
    http.Redirect(w, r, h.Cfg.FrontendURL+"/login?error=oauth_failed", http.StatusFound)
    return
  }
  h.setAuthCookie(w, token, true)

  // Redirect logic same as Node
  if out.Data.Username == nil || strings.TrimSpace(*out.Data.Username) == "" {
    q := url.QueryEscape(info.Email)
    http.Redirect(w, r, h.Cfg.FrontendURL+"/form?email="+q, http.StatusFound)
    return
  }
  if out.Data.Role == "admin" {
    http.Redirect(w, r, h.Cfg.FrontendURL+"/admin", http.StatusFound)
    return
  }
  http.Redirect(w, r, h.Cfg.FrontendURL+"/home", http.StatusFound)
}

// POST /api/auth/google-mobile
func (h *Handler) AuthGoogleMobile(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  var in struct{ AuthCode string `json:"authCode"` }
  if err := ReadJSON(r, &in); err != nil {
    h.writeError(w, http.StatusBadRequest, "Invalid JSON")
    return
  }
  if strings.TrimSpace(in.AuthCode) == "" {
    h.writeError(w, http.StatusBadRequest, "Missing authCode")
    return
  }

  info, err := h.Google.ExchangeMobile(ctx, in.AuthCode)
  if err != nil || info == nil || info.Email == "" {
    h.writeError(w, http.StatusUnauthorized, "Invalid Google auth")
    return
  }

  var out okData[userDTO]
  err = h.Pure.Post(ctx, "/api/internal/set-oauth-user", map[string]any{
    "email":      info.Email,
    "provider":   "google",
    "oauthId":    info.ID, // ✅ แก้จาก Sub -> ID
    "pictureUrl": info.Picture,
    "name":       info.Name,
  }, &out)
  if err != nil || !out.Ok || out.Data == nil {
    h.writeError(w, http.StatusUnauthorized, "Invalid Google auth")
    return
  }

  token, err := h.signToken(out.Data.ID, out.Data.Role)
  if err != nil {
    h.writeError(w, http.StatusInternalServerError, "Token error")
    return
  }
  h.setAuthCookie(w, token, true)
  WriteJSON(w, http.StatusOK, map[string]any{"role": out.Data.Role})
}
