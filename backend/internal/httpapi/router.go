package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"projectgob-backend/internal/config"
	"projectgob-backend/internal/handlers"
	"projectgob-backend/internal/pureapi"
)

func NewRouter(cfg config.Config) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// ✅ ใช้ middleware CORS ของจริง (mw_cors.go) ชื่อ cors(...)
	allowedOrigins := []string{
		"http://localhost:3000",
		"http://127.0.0.1:3000",
	}
	if cfg.FrontendURL != "" {
		allowedOrigins = append(allowedOrigins, strings.TrimRight(cfg.FrontendURL, "/"))
	}
	r.Use(cors(allowedOrigins, true))

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	p := pureapi.NewClient(cfg.PureAPIBaseURL, cfg.PureAPIKey, cfg.PureAPIInternalURL)
	h := handlers.New(cfg, p)

	// ---- Auth ----
	r.Route("/api/auth", func(ar chi.Router) {
		ar.Post("/register", h.AuthRegister)
		ar.Post("/verify-code", h.AuthVerifyCode)
		ar.Post("/complete-profile", h.AuthCompleteProfile)
		ar.Post("/login", h.AuthLogin)
		ar.Get("/status", h.AuthStatus)
		ar.Post("/logout", h.AuthLogout)
		ar.Post("/forgot-password", h.AuthForgotPassword)
		ar.Post("/reset-password", h.AuthResetPassword)

		ar.Get("/google", h.AuthGoogleStart)
		ar.Get("/google/callback", h.AuthGoogleCallback)
		ar.Get("/google-mobile", h.AuthGoogleMobileStart)
		ar.Get("/google-mobile/callback", h.AuthGoogleMobileCallback)
	})

	// ---- Public ----
	r.Get("/api/homepage", h.HomepageGet)
	r.With(h.RequireAdmin).Put("/api/homepage", h.HomepageUpdate)
	r.Get("/api/carousel", h.CarouselList)

	// ---- User ----
	r.Route("/api/users", func(ur chi.Router) {
		ur.Use(h.RequireAuth)
		ur.Get("/me", h.UsersMeGet)
		ur.Put("/me", h.UsersMePut)
		ur.Post("/me/avatar", h.UsersMeAvatar)
		ur.Delete("/me", h.UsersMeDelete)
	})

	// ---- Admin ----
	r.Route("/api/admin", func(ad chi.Router) {
		ad.Use(h.RequireAdmin)

		ad.Get("/users", h.AdminUsersList)
		ad.Put("/users/{id}", h.AdminUsersUpdateByID)
		ad.Post("/users/update", h.AdminUsersUpdate)

		ad.Get("/carousel", h.AdminCarouselList)
		ad.Post("/carousel", h.AdminCarouselCreate)
		ad.Put("/carousel/{id}", h.AdminCarouselUpdate)
		ad.Delete("/carousel/{id}", h.AdminCarouselDelete)

		ad.Put("/homepage", h.HomepageUpdate)
	})

	return r
}
