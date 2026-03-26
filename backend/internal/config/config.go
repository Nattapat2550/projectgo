package config

import (
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Port          string
	NodeEnv       string
	SessionSecret string
	JWTSecret     string

	PureAPIBaseURL     string
	PureAPIInternalURL string
	PureAPIKey         string

	GoogleClientID     string
	GoogleClientSecret string
	GoogleCallbackURI  string
	GoogleRedirectURI  string

	RefreshToken string
	SenderEmail  string
	EmailDisable bool

	FrontendURL string
}

func Load() Config {
	// รองรับการรันจากทั้ง root/backend และ root/backend/cmd/server
	_ = godotenv.Load(".env")
	_ = godotenv.Load("../.env")
	_ = godotenv.Load("../../.env") 

	cfg := Config{
		Port:          getOr("PORT", "5000"),
		NodeEnv:       getOr("NODE_ENV", "development"),
		SessionSecret: getOr("SESSION_SECRET", "change-me"),
		JWTSecret:     getOr("JWT_SECRET", "change-me"),

		PureAPIBaseURL:     strings.TrimRight(os.Getenv("PURE_API_BASE_URL"), "/"),
		PureAPIInternalURL: strings.TrimRight(os.Getenv("PURE_API_INTERNAL_URL"), "/"),
		PureAPIKey:         os.Getenv("PURE_API_KEY"),

		GoogleClientID:     firstNonEmpty(os.Getenv("GOOGLE_CLIENT_ID_WEB"), os.Getenv("GOOGLE_CLIENT_ID")),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleCallbackURI:  os.Getenv("GOOGLE_CALLBACK_URI"),
		GoogleRedirectURI:  os.Getenv("GOOGLE_REDIRECT_URI"),

		RefreshToken: os.Getenv("REFRESH_TOKEN"),
		SenderEmail:  os.Getenv("SENDER_EMAIL"),
		EmailDisable: strings.EqualFold(os.Getenv("EMAIL_DISABLE"), "true"),

		FrontendURL: getOr("FRONTEND_URL", "http://localhost:3000"),
	}

	// เช็คความครบถ้วนของตัวแปรระบบ
	if cfg.PureAPIBaseURL == "" {
		log.Println("WARN: PURE_API_BASE_URL is empty")
	}
	if cfg.PureAPIKey == "" {
		log.Println("WARN: PURE_API_KEY is empty")
	}
	if cfg.JWTSecret == "" {
		log.Println("WARN: JWT_SECRET is empty")
	}
	
	// แจ้งเตือนเรื่องการส่งอีเมล
	if !cfg.EmailDisable {
		if cfg.SenderEmail == "" || cfg.RefreshToken == "" || cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" {
			log.Println("⚠️ WARN: Email system is enabled but missing credentials (SENDER_EMAIL, REFRESH_TOKEN, GOOGLE_CLIENT_ID, or GOOGLE_CLIENT_SECRET). Emails will FAIL to send.")
		} else {
			log.Println("✅ Email system is configured.")
		}
	} else {
		log.Println("ℹ️ Email system is DISABLED (EMAIL_DISABLE=true).")
	}

	return cfg
}

func (c Config) IsProduction() bool {
	return strings.EqualFold(strings.TrimSpace(c.NodeEnv), "production")
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