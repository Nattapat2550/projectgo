package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var emailRe = regexp.MustCompile(`^\S+@\S+\.\S+$`)

type userDTO struct {
	ID                int64   `json:"id"`
	Email             string  `json:"email"`
	Username          *string `json:"username"`
	Role              string  `json:"role"`
	PasswordHash      *string `json:"password_hash"`
	IsEmailVerified   bool    `json:"is_email_verified"`
	OAuthProvider     *string `json:"oauth_provider"`
	OAuthSubject      *string `json:"oauth_subject"`
	ProfilePictureURL *string `json:"profile_picture_url"`
	CreatedAt         string  `json:"created_at"`
}

type registerReq struct {
	Email string `json:"email"`
}
type verifyReq struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}
type completeProfileReq struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}
type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}
type forgotReq struct {
	Email string `json:"email"`
}
type resetReq struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

type verifyResp struct {
	OK     bool    `json:"ok"`
	UserID *int64  `json:"userId"`
	Reason *string `json:"reason"`
}

func (h *Handler) AuthRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req registerReq
	if err := ReadJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" || !emailRe.MatchString(email) {
		h.writeError(w, http.StatusBadRequest, "Invalid email")
		return
	}

	// create user if not exists (pure-api handles idempotency)
	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/create-user-email", map[string]any{"email": email}, &user); err != nil {
		h.writeErrFrom(w, err)
		return
	}

	code := generateSixDigitCode()
	expiresAt := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	_ = h.Pure.Post(ctx, "/api/internal/store-verification-code", map[string]any{
		"userId":    user.ID,
		"code":      code,
		"expiresAt": expiresAt,
	}, nil)

	emailSent := false
	if !h.Cfg.EmailDisable {
		subject := "Your verification code"
		text := "Your verification code is: " + code + "\n\nThis code will expire in 10 minutes."
		// ✅ FIX: Mailer.Send(ctx, MailMessage)
		if err := h.Mail.Send(ctx, MailMessage{
			To:      user.Email,
			Subject: subject,
			Text:    text,
			HTML:    "",
		}); err == nil {
			emailSent = true
		}
	}

	WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "emailSent": emailSent})
}

func (h *Handler) AuthVerifyCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req verifyReq
	if err := ReadJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	code := strings.TrimSpace(req.Code)
	if email == "" || code == "" {
		h.writeError(w, http.StatusBadRequest, "Missing fields")
		return
	}

	var resp verifyResp
	if err := h.Pure.Post(ctx, "/api/internal/verify-code", map[string]any{"email": email, "code": code}, &resp); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"ok": resp.OK})
}

func (h *Handler) AuthCompleteProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req completeProfileReq
	if err := ReadJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	email := strings.TrimSpace(strings.ToLower(req.Email))
	code := strings.TrimSpace(req.Code)
	username := strings.TrimSpace(req.Username)
	password := req.Password

	if email == "" || code == "" || username == "" || password == "" {
		h.writeError(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if len(password) < 8 {
		h.writeError(w, http.StatusBadRequest, "Password too short")
		return
	}

	var vr verifyResp
	if err := h.Pure.Post(ctx, "/api/internal/verify-code", map[string]any{"email": email, "code": code}, &vr); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	if !vr.OK {
		h.writeError(w, http.StatusBadRequest, "Invalid code")
		return
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/set-username-password", map[string]any{
		"email":    email,
		"username": username,
		"password": password,
	}, &user); err != nil {
		if isUsernameUniqueViolation(err) {
			h.writeError(w, http.StatusConflict, "Username already taken")
			return
		}
		h.writeErrFrom(w, err)
		return
	}

	token, err := h.signToken(user.ID, user.Role)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Token error")
		return
	}
	h.setAuthCookie(w, token, req.Remember)

	WriteJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": token,
		"user":  user,
	})
}

func (h *Handler) AuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req loginReq
	if err := ReadJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" || req.Password == "" {
		h.writeError(w, http.StatusBadRequest, "Missing fields")
		return
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/find-user-by-email", map[string]any{"email": email}, &user); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	if user.PasswordHash == nil || *user.PasswordHash == "" {
		h.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(req.Password)); err != nil {
		h.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	token, err := h.signToken(user.ID, user.Role)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Token error")
		return
	}
	h.setAuthCookie(w, token, req.Remember)

	WriteJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": token,
		"user":  user,
	})
}

func (h *Handler) AuthStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tok := extractTokenFromReq(r)
	if tok == "" {
		WriteJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}

	claims, err := h.parseToken(tok)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/find-user", map[string]any{"id": claims.UserID}, &user); err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user})
}

func (h *Handler) AuthLogout(w http.ResponseWriter, _ *http.Request) {
	h.clearAuthCookie(w)
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) AuthForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req forgotReq
	if err := ReadJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" {
		h.writeError(w, http.StatusBadRequest, "Missing email")
		return
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/find-user-by-email", map[string]any{"email": email}, &user); err != nil {
		// do not leak existence
		WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "emailSent": false})
		return
	}

	token := randomTokenHex(32)
	expiresAt := time.Now().Add(30 * time.Minute).Format(time.RFC3339)

	_ = h.Pure.Post(ctx, "/api/internal/create-reset-token", map[string]any{
		"userId":    user.ID,
		"token":     token,
		"expiresAt": expiresAt,
	}, nil)

	emailSent := false
	if !h.Cfg.EmailDisable {
		resetLink := strings.TrimRight(h.Cfg.FrontendURL, "/") + "/reset?token=" + token
		subject := "Reset your password"
		text := "Click this link to reset your password:\n" + resetLink + "\n\nThis link expires in 30 minutes."

		// ✅ FIX: Mailer.Send(ctx, MailMessage)
		if err := h.Mail.Send(ctx, MailMessage{
			To:      user.Email,
			Subject: subject,
			Text:    text,
			HTML:    "",
		}); err == nil {
			emailSent = true
		}
	}

	WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "emailSent": emailSent})
}

func (h *Handler) AuthResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req resetReq
	if err := ReadJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	token := strings.TrimSpace(req.Token)
	newPass := req.NewPassword
	if token == "" || newPass == "" {
		h.writeError(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if len(newPass) < 8 {
		h.writeError(w, http.StatusBadRequest, "Password too short")
		return
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/consume-reset-token", map[string]any{"token": token}, &user); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid or expired token")
		return
	}

	if err := h.Pure.Post(ctx, "/api/internal/set-password", map[string]any{"id": user.ID, "password": newPass}, nil); err != nil {
		h.writeErrFrom(w, err)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- helpers ----

func generateSixDigitCode() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	code := 100000 + (n % 900000)
	return strconv.Itoa(code)
}

func randomTokenHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
