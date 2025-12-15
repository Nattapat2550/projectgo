package handlers

import (
  "context"
  "net/http"
  "time"

  "github.com/golang-jwt/jwt/v5"
)

type UserClaims struct {
  ID   int64  `json:"id"`
  Role string `json:"role"`
}

type jwtClaims struct {
  ID   int64  `json:"id"`
  Role string `json:"role"`
  // Compatibility with older code that used is_admin
  IsAdmin bool `json:"is_admin"`
  jwt.RegisteredClaims
}

type ctxKey int

const userKey ctxKey = 1

func (h *Handler) signToken(userID int64, role string) (string, error) {
  now := time.Now()
  cl := jwtClaims{
    ID:     userID,
    Role:   role,
    IsAdmin: role == "admin",
    RegisteredClaims: jwt.RegisteredClaims{
      ExpiresAt: jwt.NewNumericDate(now.Add(30 * 24 * time.Hour)),
      IssuedAt:  jwt.NewNumericDate(now),
    },
  }
  t := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
  return t.SignedString([]byte(h.Cfg.JWTSecret))
}

func (h *Handler) setAuthCookie(w http.ResponseWriter, token string, remember bool) {
  maxAge := 24 * time.Hour
  if remember {
    maxAge = 30 * 24 * time.Hour
  }

  // IMPORTANT:
  // - Production (Render HTTPS + cross-site): must be SameSite=None + Secure=true
  // - Dev (localhost): many browsers reject SameSite=None without Secure, so use Lax.
  sameSite := http.SameSiteLaxMode
  secure := false
  if h.Cfg.NodeEnv == "production" {
    sameSite = http.SameSiteNoneMode
    secure = true
  }

  c := &http.Cookie{
    Name:     "token",
    Value:    token,
    Path:     "/",
    HttpOnly: true,
    Secure:   secure,
    SameSite: sameSite,
    MaxAge:   int(maxAge.Seconds()),
  }
  http.SetCookie(w, c)
}

func (h *Handler) clearAuthCookie(w http.ResponseWriter) {
  sameSite := http.SameSiteLaxMode
  secure := false
  if h.Cfg.NodeEnv == "production" {
    sameSite = http.SameSiteNoneMode
    secure = true
  }

  c := &http.Cookie{
    Name:     "token",
    Value:    "",
    Path:     "/",
    HttpOnly: true,
    Secure:   secure,
    SameSite: sameSite,
    MaxAge:   -1,
  }
  http.SetCookie(w, c)
}

func extractTokenFromReq(r *http.Request) string {
  if c, err := r.Cookie("token"); err == nil && c.Value != "" {
    return c.Value
  }
  if bt := bearerToken(r); bt != "" {
    return bt
  }
  return ""
}

func (h *Handler) parseToken(token string) (*jwtClaims, error) {
  parsed, err := jwt.ParseWithClaims(token, &jwtClaims{}, func(t *jwt.Token) (any, error) {
    return []byte(h.Cfg.JWTSecret), nil
  })
  if err != nil {
    return nil, err
  }
  cl, ok := parsed.Claims.(*jwtClaims)
  if !ok || !parsed.Valid {
    return nil, jwt.ErrTokenInvalidClaims
  }
  return cl, nil
}

func (h *Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    token := extractTokenFromReq(r)
    if token == "" {
      h.writeError(w, http.StatusUnauthorized, "Unauthorized")
      return
    }
    cl, err := h.parseToken(token)
    if err != nil {
      h.writeError(w, http.StatusUnauthorized, "Unauthorized")
      return
    }

    u := UserClaims{ID: cl.ID, Role: cl.Role}
    ctx := context.WithValue(r.Context(), userKey, u)
    next(w, r.WithContext(ctx))
  }
}

func (h *Handler) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
  return h.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
    u := GetUser(r)
    if u.Role != "admin" {
      // Backward compatibility: accept tokens that set is_admin=true
      token := extractTokenFromReq(r)
      if token != "" {
        if cl, err := h.parseToken(token); err == nil && cl.IsAdmin {
          next(w, r)
          return
        }
      }
      h.writeError(w, http.StatusForbidden, "Admin only")
      return
    }
    next(w, r)
  })
}

func GetUser(r *http.Request) UserClaims {
  if v := r.Context().Value(userKey); v != nil {
    if u, ok := v.(UserClaims); ok {
      return u
    }
  }
  return UserClaims{}
}
