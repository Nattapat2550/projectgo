package handlers

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// GET /api/auth/google
func (h *Handler) AuthGoogleStart(w http.ResponseWriter, r *http.Request) {
	u, ok := h.Google.AuthURL("state")
	if !ok {
		h.writeError(w, http.StatusServiceUnavailable, "Google login is temporarily unavailable. Please try again in a moment.")
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// GET /api/auth/google/callback
func (h *Handler) AuthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		h.writeError(w, http.StatusBadRequest, "Missing code")
		return
	}

	info, err := h.Google.ExchangeWeb(ctx, code) // returns *googleUserInfo
	if err != nil || info == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Google login is temporarily unavailable. Please try again in a moment.")
		return
	}

	user, err := h.setOAuthUser(ctx, info)
	if err != nil {
		h.writeErrFrom(w, err)
		return
	}

	token, err := h.signToken(user.ID, user.Role)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Token error")
		return
	}

	h.setAuthCookie(w, token, true)

	front := strings.TrimRight(h.Cfg.FrontendURL, "/")
	frag := url.Values{}
	frag.Set("token", token)
	frag.Set("provider", "google")

	http.Redirect(w, r, front+"/#"+frag.Encode(), http.StatusFound)
}

// GET /api/auth/google-mobile
func (h *Handler) AuthGoogleMobileStart(w http.ResponseWriter, r *http.Request) {
	u, ok := h.Google.AuthURL("state")
	if !ok {
		h.writeError(w, http.StatusServiceUnavailable, "Google login is temporarily unavailable. Please try again in a moment.")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "url": u})
}

// GET /api/auth/google-mobile/callback?code=...
func (h *Handler) AuthGoogleMobileCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		h.writeError(w, http.StatusBadRequest, "Missing code")
		return
	}

	info, err := h.Google.ExchangeMobile(ctx, code) // returns *googleUserInfo
	if err != nil || info == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Google login is temporarily unavailable. Please try again in a moment.")
		return
	}

	user, err := h.setOAuthUser(ctx, info)
	if err != nil {
		h.writeErrFrom(w, err)
		return
	}

	token, err := h.signToken(user.ID, user.Role)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Token error")
		return
	}

	h.setAuthCookie(w, token, true)
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "token": token, "user": user})
}

// ✅ รับ pointer ตามของจริงใน google_oauth.go: ExchangeWeb/Mobile คืน *googleUserInfo
func (h *Handler) setOAuthUser(ctx context.Context, info *googleUserInfo) (userDTO, error) {
	email := strings.ToLower(strings.TrimSpace(info.Email))
	subject := strings.TrimSpace(info.ID) // ของโปรเจคเดิมใช้ field ID เป็น unique subject
	pic := strings.TrimSpace(info.Picture)

	payload := map[string]any{
		"provider":            "google",
		"subject":             subject,
		"email":               email,
		"profile_picture_url": pic,
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/set-oauth-user", payload, &user); err != nil {
		return userDTO{}, err
	}
	return user, nil
}
