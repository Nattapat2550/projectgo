package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var emailRegex = regexp.MustCompile(`^\S+@\S+\.\S+$`)

// userDTO matches the structure returned by pure-api
type userDTO struct {
	ID                int64   `json:"id"`
	Username          *string `json:"username"`
	Email             string  `json:"email"`
	Role              string  `json:"role"`
	PasswordHash      *string `json:"password_hash"`
	IsEmailVerified   bool    `json:"is_email_verified"`
	ProfilePictureURL *string `json:"profile_picture_url"`
}

type okData[T any] struct {
	Ok   bool `json:"ok"`
	Data *T   `json:"data"`
}

// --- /api/auth/register ---
func (h *Handler) AuthRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Email   string `json:"email"`
		Preview bool   `json:"preview"`
		Mode    string `json:"mode"`
	}
	if err := ReadJSON(r, &in); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// 1. Check for preview mode (Node logic parity)
	qPreview := r.URL.Query().Get("preview") == "1"
	if qPreview || in.Preview || in.Mode == "preview" {
		WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "preview": true})
		return
	}

	email := strings.TrimSpace(in.Email)
	if email == "" || !emailRegex.MatchString(email) {
		h.writeError(w, http.StatusBadRequest, "Invalid email")
		return
	}

	// 2. Find existing user
	var found okData[userDTO]
	// Ignore error here to match Node behavior (treat as not found)
	_ = h.Pure.Post(ctx, "/api/internal/find-user", map[string]any{"email": email}, &found)

	if found.Ok && found.Data != nil && found.Data.IsEmailVerified {
		WriteJSON(w, http.StatusConflict, map[string]any{"error": "Email already registered"})
		return
	}

	// 3. Create user if not exists
	user := found.Data
	if user == nil {
		var created okData[userDTO]
		// FIX: Handle network error as 503 (Node behavior), instead of 500
		if err := h.Pure.Post(ctx, "/api/internal/create-user-email", map[string]any{"email": email}, &created); err != nil {
			h.writeError(w, http.StatusServiceUnavailable, "Pure API is temporarily unavailable (rate-limited/blocked). Please try again.")
			return
		}
		
		// Pure API logical error or rate-limited (matches Node 503 response)
		if !created.Ok || created.Data == nil {
			h.writeError(w, http.StatusServiceUnavailable, "Pure API is temporarily unavailable (rate-limited/blocked). Please try again.")
			return
		}
		user = created.Data
	}

	// 4. Generate & Store Code
	code := generateSixDigitCode()
	expiresAt := time.Now().Add(10 * time.Minute).UTC()

	// FIX: Handle store error as 503 (Node behavior), instead of 500
	if err := h.Pure.Post(ctx, "/api/internal/store-verification-code", map[string]any{
		"userId":    user.ID,
		"code":      code,
		"expiresAt": expiresAt,
	}, nil); err != nil {
		h.writeError(w, http.StatusServiceUnavailable, "Cannot store verification code. Please try again.")
		return
	}

	// 5. Send Email (Text only for better deliverability/Outlook)
	emailSent := true
	err := h.Mail.Send(ctx, MailMessage{
		To:      email,
		Subject: "Your verification code",
		Text:    fmt.Sprintf("Your verification code is: %s\n\nThis code expires in 10 minutes.", code),
		HTML:    "", 
	})
	if err != nil {
		emailSent = false
		fmt.Printf("sendEmail failed: %v\n", err)
	}

	WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "emailSent": emailSent})
}

// --- /api/auth/verify-code ---
func (h *Handler) AuthVerifyCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := ReadJSON(r, &in); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	email := strings.TrimSpace(in.Email)
	code := strings.TrimSpace(in.Code)
	if email == "" || code == "" {
		h.writeError(w, http.StatusBadRequest, "Missing email or code")
		return
	}

	var resp map[string]any
	if err := h.Pure.Post(ctx, "/api/internal/verify-code", map[string]any{"email": email, "code": code}, &resp); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	if ok, _ := resp["ok"].(bool); !ok {
		if reason, _ := resp["reason"].(string); reason == "no_user" {
			h.writeError(w, http.StatusNotFound, "User not found")
			return
		}
		h.writeError(w, http.StatusBadRequest, "Invalid or expired code")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- /api/auth/complete-profile ---
func (h *Handler) AuthCompleteProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := ReadJSON(r, &in); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	email := strings.TrimSpace(in.Email)
	username := strings.TrimSpace(in.Username)
	password := in.Password

	if email == "" || username == "" || password == "" {
		h.writeError(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if len(username) < 3 {
		h.writeError(w, http.StatusBadRequest, "Username too short")
		return
	}
	if len(password) < 8 {
		h.writeError(w, http.StatusBadRequest, "Password too short")
		return
	}

	var out okData[userDTO]
	err := h.Pure.Post(ctx, "/api/internal/set-username-password", map[string]any{
		"email":    email,
		"username": username,
		"password": password, 
	}, &out)
	if err != nil {
		e := strings.ToLower(err.Error())
		if (strings.Contains(e, "username") && strings.Contains(e, "taken")) ||
			strings.Contains(e, "duplicate key") ||
			strings.Contains(e, "users_username_key") {
			WriteJSON(w, http.StatusConflict, map[string]any{"error": "Username already taken"})
			return
		}
		h.writeErrFrom(w, err)
		return
	}
	if !out.Ok || out.Data == nil {
		h.writeError(w, http.StatusUnauthorized, "Email not verified")
		return
	}

	token, err := h.signToken(out.Data.ID, out.Data.Role)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Token error")
		return
	}
	h.setAuthCookie(w, token, true)

	WriteJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": token,
		"role":  out.Data.Role,
		"user": map[string]any{
			"id":                  out.Data.ID,
			"email":               out.Data.Email,
			"username":            out.Data.Username,
			"role":                out.Data.Role,
			"profile_picture_url": out.Data.ProfilePictureURL,
		},
	})
}

// --- /api/auth/login ---
func (h *Handler) AuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Remember bool   `json:"remember"`
	}
	if err := ReadJSON(r, &in); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	email := strings.TrimSpace(in.Email)
	pass := in.Password

	var out okData[userDTO]
	if err := h.Pure.Post(ctx, "/api/internal/find-user", map[string]any{"email": email}, &out); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	if !out.Ok || out.Data == nil || out.Data.PasswordHash == nil || strings.TrimSpace(*out.Data.PasswordHash) == "" {
		h.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*out.Data.PasswordHash), []byte(pass)); err != nil {
		h.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	token, err := h.signToken(out.Data.ID, out.Data.Role)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Token error")
		return
	}
	h.setAuthCookie(w, token, in.Remember)

	WriteJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"role":  out.Data.Role,
		"user": map[string]any{
			"id":                  out.Data.ID,
			"email":               out.Data.Email,
			"username":            out.Data.Username,
			"role":                out.Data.Role,
			"profile_picture_url": out.Data.ProfilePictureURL,
		},
	})
}

// --- /api/auth/logout ---
func (h *Handler) AuthLogout(w http.ResponseWriter, r *http.Request) {
	h.clearAuthCookie(w)
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- /api/auth/status ---
func (h *Handler) AuthStatus(w http.ResponseWriter, r *http.Request) {
	token := extractTokenFromReq(r)
	if token == "" {
		WriteJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	cl, err := h.parseToken(token)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	role := cl.Role
	if role == "" {
		role = "user"
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"id":            cl.ID,
		"role":          role,
	})
}

// --- /api/auth/forgot-password ---
func (h *Handler) AuthForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Email string `json:"email"`
	}
	if err := ReadJSON(r, &in); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	email := strings.TrimSpace(in.Email)
	if email == "" {
		h.writeError(w, http.StatusBadRequest, "Missing email")
		return
	}

	rawToken := randomHex(32)
	expiresAt := time.Now().Add(30 * time.Minute).UTC()

	var out okData[userDTO]
	_ = h.Pure.Post(ctx, "/api/internal/create-reset-token", map[string]any{
		"email":     email,
		"token":     rawToken,
		"expiresAt": expiresAt,
	}, &out)

	if out.Ok && out.Data != nil {
		link := strings.TrimRight(h.Cfg.FrontendURL, "/") + "/reset.html?token=" + url.QueryEscape(rawToken)
		_ = h.Mail.Send(ctx, MailMessage{
			To:      email,
			Subject: "Password reset",
			Text:    fmt.Sprintf("Reset your password using this link (valid 30 minutes):\n\n%s", link),
			HTML:    "",
		})
	}

	WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- /api/auth/reset-password ---
func (h *Handler) AuthResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}
	if err := ReadJSON(r, &in); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	token := strings.TrimSpace(in.Token)
	newPass := in.NewPassword
	if token == "" || newPass == "" {
		h.writeError(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if len(newPass) < 8 {
		h.writeError(w, http.StatusBadRequest, "Password too short")
		return
	}

	var out okData[userDTO]
	if err := h.Pure.Post(ctx, "/api/internal/consume-reset-token", map[string]any{"token": token}, &out); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	if !out.Ok || out.Data == nil {
		h.writeError(w, http.StatusBadRequest, "Invalid or expired token")
		return
	}

	if err := h.Pure.Post(ctx, "/api/internal/set-password", map[string]any{
		"userId":      out.Data.ID,
		"newPassword": newPass,
	}, nil); err != nil {
		h.writeErrFrom(w, err)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSixDigitCode() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	v := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	v = v % 1000000
	return fmt.Sprintf("%06d", v)
}