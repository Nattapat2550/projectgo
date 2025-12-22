package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ctxKey string

const (
	ctxUser ctxKey = "user"
)

type AuthUser struct {
	ID   int64  `json:"id"`
	Role string `json:"role"`
}

type jwtClaims struct {
	UserID int64  `json:"userId"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractTokenFromReq(r)
		if token == "" {
			h.writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		claims, err := h.parseToken(token)
		if err != nil {
			h.writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		u := &AuthUser{ID: claims.UserID, Role: claims.Role}
		ctx := context.WithValue(r.Context(), ctxUser, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *Handler) RequireAdmin(next http.Handler) http.Handler {
	return h.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := GetUser(r)
		if u == nil || u.Role != "admin" {
			h.writeError(w, http.StatusForbidden, "Forbidden")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func GetUser(r *http.Request) *AuthUser {
	v := r.Context().Value(ctxUser)
	if v == nil {
		return nil
	}
	u, _ := v.(*AuthUser)
	return u
}

func extractTokenFromReq(r *http.Request) string {
	// 1) Authorization: Bearer ...
	if t := bearerToken(r); t != "" {
		return t
	}
	// 2) Cookie
	c, err := r.Cookie("token")
	if err == nil && c != nil && strings.TrimSpace(c.Value) != "" {
		return strings.TrimSpace(c.Value)
	}
	return ""
}

func (h *Handler) signToken(userID int64, role string) (string, error) {
	now := time.Now()
	claims := jwtClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(7 * 24 * time.Hour)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(h.Cfg.JWTSecret))
}

func (h *Handler) parseToken(token string) (*jwtClaims, error) {
	claims := &jwtClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(_ *jwt.Token) (any, error) {
		return []byte(h.Cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	if claims.UserID <= 0 {
		return nil, errors.New("invalid claims")
	}
	return claims, nil
}

func (h *Handler) setAuthCookie(w http.ResponseWriter, token string, remember bool) {
	c := &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.Cfg.IsProduction(),
	}
	if remember {
		c.MaxAge = int((7 * 24 * time.Hour).Seconds())
		c.Expires = time.Now().Add(7 * 24 * time.Hour)
	}
	http.SetCookie(w, c)
}

func (h *Handler) clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.Cfg.IsProduction(),
	})
}
