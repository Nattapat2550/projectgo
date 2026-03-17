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

// ------ REGISTER ------
func (h *Handler) AuthRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req registerReq
	if err := ReadJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON"})
		return
	}
	
	// ✅ เอา strings.ToLower ออก เพื่อให้ตรงกับโครงสร้าง Node.js 100% (ป้องกันหา email ไม่เจอ)
	email := strings.TrimSpace(req.Email)
	if email == "" || !emailRe.MatchString(email) {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid email"})
		return
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/create-user-email", map[string]any{"email": email}, &user); err != nil {
		WriteJSON(w, http.StatusConflict, map[string]any{"error": "Email already registered"})
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
		if err := h.Mail.Send(ctx, MailMessage{
			To:      user.Email,
			Subject: subject,
			Text:    text,
			HTML:    "",
		}); err == nil {
			emailSent = true
		}
	}

	WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "emailSent": emailSent})
}

// ------ VERIFY CODE ------
func (h *Handler) AuthVerifyCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req verifyReq
	if err := ReadJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON"})
		return
	}
	email := strings.TrimSpace(req.Email)
	code := strings.TrimSpace(req.Code)
	if email == "" || code == "" {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Missing email or code"})
		return
	}

	var resp verifyResp
	if err := h.Pure.Post(ctx, "/api/internal/verify-code", map[string]any{"email": email, "code": code}, &resp); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid or expired code"})
		return
	}
	
	if !resp.OK {
		if resp.Reason != nil && *resp.Reason == "no_user" {
			WriteJSON(w, http.StatusNotFound, map[string]any{"error": "User not found"})
		} else {
			WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid or expired code"})
		}
		return
	}
	
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ------ COMPLETE PROFILE ------
func (h *Handler) AuthCompleteProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req completeProfileReq
	if err := ReadJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON"})
		return
	}

	email := strings.TrimSpace(req.Email)
	username := strings.TrimSpace(req.Username)
	password := req.Password

	if email == "" || username == "" || password == "" {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Missing fields"})
		return
	}
	if len(username) < 3 {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Username too short"})
		return
	}
	if len(password) < 8 {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Password too short"})
		return
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/set-username-password", map[string]any{
		"email":    email,
		"username": username,
		"password": password,
	}, &user); err != nil {
		if isUsernameUniqueViolation(err) {
			WriteJSON(w, http.StatusConflict, map[string]any{"error": "Username already taken"})
			return
		}
		WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "Email not verified"})
		return
	}

	token, err := h.signToken(user.ID, user.Role)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "Internal error"})
		return
	}
	h.setAuthCookie(w, token, req.Remember)

	WriteJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": token,
		"role":  user.Role,
		"user": map[string]any{
			"id":                  user.ID,
			"email":               user.Email,
			"username":            user.Username,
			"role":                user.Role,
			"profile_picture_url": user.ProfilePictureURL,
		},
	})
}

// ------ LOGIN ------
func (h *Handler) AuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req loginReq
	if err := ReadJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON"})
		return
	}
	email := strings.TrimSpace(req.Email)
	if email == "" || req.Password == "" {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid credentials"})
		return
	}

	var user userDTO
	// ✅ เปลี่ยนมาใช้ WriteJSON ตอบกลับเป็นรูปแบบ {"error": "..."} เพื่อให้ React ดักจับและโชว์แจ้งเตือนได้ถูกต้อง
	if err := h.Pure.Post(ctx, "/api/internal/find-user-by-email", map[string]any{"email": email}, &user); err != nil {
		WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "Invalid credentials"})
		return
	}
	if user.PasswordHash == nil || *user.PasswordHash == "" {
		WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "Invalid credentials"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(req.Password)); err != nil {
		WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "Invalid credentials"})
		return
	}

	token, err := h.signToken(user.ID, user.Role)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "Internal error"})
		return
	}
	h.setAuthCookie(w, token, req.Remember)

	WriteJSON(w, http.StatusOK, map[string]any{
		"role":  user.Role,
		"token": token,
		"user": map[string]any{
			"id":                  user.ID,
			"email":               user.Email,
			"username":            user.Username,
			"role":                user.Role,
			"profile_picture_url": user.ProfilePictureURL,
		},
	})
}

// ------ STATUS ------
func (h *Handler) AuthStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tok := extractTokenFromReq(r)
	if tok == "" {
		WriteJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}

	claims, err := h.parseToken(tok)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/find-user", map[string]any{"id": claims.UserID}, &user); err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	
	WriteJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"id":            user.ID,
		"role":          user.Role,
	})
}

// ------ LOGOUT ------
func (h *Handler) AuthLogout(w http.ResponseWriter, _ *http.Request) {
	h.clearAuthCookie(w)
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ------ FORGOT / RESET PASSWORD ------
func (h *Handler) AuthForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req forgotReq
	if err := ReadJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON"})
		return
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Missing email"})
		return
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/find-user-by-email", map[string]any{"email": email}, &user); err != nil {
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
		subject := "Password reset"
		text := "Reset your password using this link (valid 30 minutes):\n\n" + resetLink

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
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON"})
		return
	}
	token := strings.TrimSpace(req.Token)
	newPass := req.NewPassword
	if token == "" || newPass == "" {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Missing fields"})
		return
	}
	if len(newPass) < 8 {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Password too short"})
		return
	}

	var user userDTO
	if err := h.Pure.Post(ctx, "/api/internal/consume-reset-token", map[string]any{"token": token}, &user); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid or expired token"})
		return
	}

	if err := h.Pure.Post(ctx, "/api/internal/set-password", map[string]any{"id": user.ID, "password": newPass}, nil); err != nil {
		WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "Internal error"})
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