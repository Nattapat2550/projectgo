package config

import (
  "log"
  "os"
  "path/filepath"
  "strings"

  "github.com/joho/godotenv"
)

type Config struct {
  Port          string
  NodeEnv       string
  SessionSecret string
  JWTSecret     string

  PureAPIBaseURL string
  PureAPIKey     string

  GoogleClientID     string
  GoogleClientSecret string
  GoogleCallbackURI  string
  GoogleRedirectURI  string

  RefreshToken string
  SenderEmail  string
  EmailDisable bool

  FrontendURL string
}

// Load env similar to the old Node backend:
// - tries backend/.env
// - then tries repo root .env (../.env)
func Load() Config {
  // best-effort load
  _ = godotenv.Load(filepath.Join(".", ".env"))
  _ = godotenv.Overload(filepath.Join("..", ".env"))

  cfg := Config{
    Port:          getOr("PORT", "5000"),
    NodeEnv:       getOr("NODE_ENV", "development"),
    SessionSecret: os.Getenv("SESSION_SECRET"),
    JWTSecret:     os.Getenv("JWT_SECRET"),

    PureAPIBaseURL: strings.TrimRight(os.Getenv("PURE_API_BASE_URL"), "/"),
    PureAPIKey:     os.Getenv("PURE_API_KEY"),

    GoogleClientID:     firstNonEmpty(os.Getenv("GOOGLE_CLIENT_ID_WEB"), os.Getenv("GOOGLE_CLIENT_ID")),
    GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    GoogleCallbackURI:  os.Getenv("GOOGLE_CALLBACK_URI"),
    GoogleRedirectURI:  os.Getenv("GOOGLE_REDIRECT_URI"),

    RefreshToken: os.Getenv("REFRESH_TOKEN"),
    SenderEmail:  os.Getenv("SENDER_EMAIL"),
    EmailDisable: strings.EqualFold(os.Getenv("EMAIL_DISABLE"), "true"),

    FrontendURL: getOr("FRONTEND_URL", "http://localhost:3000"),
  }

  // basic required checks (fail fast to avoid silent bugs)
  if cfg.JWTSecret == "" {
    log.Println("[WARN] JWT_SECRET is empty")
  }
  if cfg.PureAPIBaseURL == "" {
    log.Println("[WARN] PURE_API_BASE_URL is empty")
  }
  if cfg.PureAPIKey == "" {
    log.Println("[WARN] PURE_API_KEY is empty")
  }
  return cfg
}

func getOr(k, def string) string {
  if v := os.Getenv(k); v != "" {
    return v
  }
  return def
}

func firstNonEmpty(a, b string) string {
  if a != "" {
    return a
  }
  return b
}
