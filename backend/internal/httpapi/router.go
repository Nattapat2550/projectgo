package httpapi

import (
  "net/http"
  "strings"
  "time"

  "github.com/go-chi/chi/v5"
  "github.com/go-chi/chi/v5/middleware"

  "projectgob-backend/internal/config"
  "projectgob-backend/internal/handlers"
  "projectgob-backend/internal/pureapi"
)

func NewRouter(cfg config.Config) http.Handler {
  r := chi.NewRouter()

  // --- middlewares (match old Express behavior as close as possible)
  r.Use(middleware.RequestID)
  r.Use(middleware.RealIP)
  r.Use(middleware.Logger)
  r.Use(middleware.Recoverer)
  r.Use(middleware.Timeout(60 * time.Second))
  r.Use(middleware.Compress(5))

  // Basic security headers (Helmet-ish)
  r.Use(securityHeaders)

  // Rate limit: 400 req / 15min per IP (no external deps)
  r.Use(rateLimit(400, 15*time.Minute, ipKeyFunc(cfg.NodeEnv == "production")))

  // CORS (front/back different domains, need credentials)
  allowedOrigins := []string{cfg.FrontendURL}
  if cfg.NodeEnv != "production" {
    allowedOrigins = append(allowedOrigins, "http://localhost:3000", "http://127.0.0.1:3000")
  }
  r.Use(cors(allowedOrigins))

  // Build dependencies
  p := pureapi.NewClient(cfg.PureAPIBaseURL, cfg.PureAPIKey)
  h := handlers.New(cfg, p)

  // Routes (same paths as the old Node backend)
  r.Get("/health", h.Health)

  r.Route("/api/auth", func(ar chi.Router) {
    ar.Post("/register", h.AuthRegister)
    ar.Post("/verify-code", h.AuthVerifyCode)
    ar.Post("/complete-profile", h.AuthCompleteProfile)
    ar.Post("/login", h.AuthLogin)
    ar.Post("/logout", h.AuthLogout)
    ar.Get("/google", h.AuthGoogleStart)
    ar.Get("/google/callback", h.AuthGoogleCallback)
    ar.Post("/google-mobile", h.AuthGoogleMobile)
    ar.Post("/forgot-password", h.AuthForgotPassword)
    ar.Post("/reset-password", h.AuthResetPassword)
    ar.Get("/status", h.AuthStatus)
  })

  r.Route("/api/users", func(ur chi.Router) {
    ur.Get("/me", h.RequireAuth(h.UsersMeGet))
    ur.Put("/me", h.RequireAuth(h.UsersMePut))
    ur.Delete("/me", h.RequireAuth(h.UsersMeDelete))
    ur.Post("/me/avatar", h.RequireAuth(h.UsersMeAvatar))
  })

  r.Route("/api/admin", func(ad chi.Router) {
    ad.Post("/users/update", h.RequireAdmin(h.AdminUsersUpdate))
  })

  r.Route("/api/homepage", func(hr chi.Router) {
    hr.Get("/", h.HomepageGet)
    hr.Post("/update", h.HomepageUpdate)
  })

  r.Route("/api/carousel", func(cr chi.Router) {
    cr.Get("/", h.CarouselList)
  })

  r.Route("/api/download", func(dr chi.Router) {
    dr.Get("/windows", h.DownloadWindows)
    dr.Get("/android", h.DownloadAndroid)
  })

  // fallback 404 JSON
  r.NotFound(func(w http.ResponseWriter, r *http.Request) {
    handlers.WriteJSON(w, http.StatusNotFound, map[string]any{
      "error":   true,
      "message": "Not found",
      "path":    r.URL.Path,
    })
  })

  return r
}

func securityHeaders(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("Referrer-Policy", "no-referrer")
    w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    // Similar to old helmet.contentSecurityPolicy (loose + safe defaults for SPA)
    w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; style-src 'self' 'unsafe-inline'")
    next.ServeHTTP(w, r)
  })
}

func ipKeyFunc(trustProxy bool) func(r *http.Request) (string, error) {
  return func(r *http.Request) (string, error) {
    if trustProxy {
      // Render sets X-Forwarded-For: client, proxy
      if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        parts := strings.Split(xff, ",")
        if len(parts) > 0 {
          return strings.TrimSpace(parts[0]), nil
        }
      }
    }
    // r.RemoteAddr is "ip:port"
    host := r.RemoteAddr
    if i := strings.LastIndex(host, ":"); i >= 0 {
      host = host[:i]
    }
    return host, nil
  }
}
