package httpapi_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"projectgob-backend/internal/config"
	"projectgob-backend/internal/httpapi"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// ==========================================
// 🛠 Helpers
// ==========================================

func generateTestToken(userID int64, role string, secret string) string {
	claims := jwt.MapClaims{
		"userId": userID,
		"role":   role,
		"exp":    time.Now().Add(1 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, _ := token.SignedString([]byte(secret))
	return t
}

func TestComprehensiveSystem(t *testing.T) {
	jwtSecret := "supersecret_test_jwt_key_123456"

	// 🛑 1. Mock Pure API Server
	pureMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")

		switch {
		// --- Auth Flow ---
		case strings.Contains(path, "create-user"):
			w.Write([]byte(`{"id": 1, "email": "test@example.com"}`))
		case strings.Contains(path, "store-verification-code") || strings.Contains(path, "verify-code"):
			w.Write([]byte(`{"ok": true, "userId": 1}`))
		case strings.Contains(path, "set-username-password"):
			w.Write([]byte(`{"id": 1, "email": "test@example.com", "username": "Tester", "role": "user"}`))
		case strings.Contains(path, "create-reset-token") || strings.Contains(path, "consume-reset-token"):
			w.Write([]byte(`{"id": 1, "email": "test@example.com"}`))
		case strings.Contains(path, "set-password"):
			w.Write([]byte(`{"ok": true}`))
		case strings.Contains(path, "find-user"):
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			
			// จำลองเคสหาไม่เจอ
			if email, ok := body["email"].(string); ok && email == "notfound@example.com" {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": {"message": "User not found"}}`))
				return
			}
			
			hash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
			json.NewEncoder(w).Encode(map[string]any{
				"id": 1, "email": "test@example.com", "username": "Tester",
				"role": "user", "password_hash": string(hash),
			})

		// --- User & Admin ---
		case strings.Contains(path, "delete-user"):
			w.Write([]byte(`{"ok": true}`))
		case strings.Contains(path, "admin/users/update"):
			w.Write([]byte(`{"id": 1, "role": "admin"}`))
		case strings.Contains(path, "admin/users"):
			w.Write([]byte(`[{"id": 1, "email": "test@example.com", "role": "user"}]`))
		case strings.Contains(path, "carousel/create") || strings.Contains(path, "carousel/update") || strings.Contains(path, "carousel/delete"):
			w.Write([]byte(`{"ok": true}`))
		case strings.Contains(path, "carousel/list"):
			w.Write([]byte(`[{"id": 1, "title": "Slide 1"}]`))
		case strings.Contains(path, "homepage/list"):
			w.Write([]byte(`[{"section_name": "welcome_header", "content": "Hello"}]`))
		case strings.Contains(path, "homepage/update"):
			w.Write([]byte(`{"ok": true}`))

		default:
			w.Write([]byte(`{"ok": true}`))
		}
	}))
	defer pureMock.Close()

	// 🛑 2. Config & Router
	cfg := config.Config{
		PureAPIBaseURL: pureMock.URL,
		EmailDisable:   true,
		JWTSecret:      jwtSecret,
		FrontendURL:    "http://localhost:3000",
		GoogleClientID: "mock-client-id",
		GoogleClientSecret: "mock-secret",
		GoogleCallbackURI: "http://localhost:3000/callback",
	}
	router := httpapi.NewRouter(cfg)

	execute := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	userToken := generateTestToken(1, "user", jwtSecret)
	adminToken := generateTestToken(99, "admin", jwtSecret)

	// ==========================================
	// 1. AUTH FLOW & LOGIN TESTS
	// ==========================================
	t.Run("AUTH: Register Success", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/register", strings.NewReader(`{"email": "test@example.com"}`))
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("AUTH: Verify Code", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/verify-code", strings.NewReader(`{"email": "test@example.com", "code": "123456"}`))
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("AUTH: Complete Profile", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/complete-profile", strings.NewReader(`{"email": "test@example.com", "code": "123456", "username": "Test", "password": "Password123!"}`))
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("AUTH: Forgot Password", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/forgot-password", strings.NewReader(`{"email": "test@example.com"}`))
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("AUTH: Reset Password", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/reset-password", strings.NewReader(`{"token": "mocktoken", "newPassword": "NewPassword123!"}`))
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("AUTH: Google OAuth URL", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/auth/google", nil)
		rr := execute(req)
		if rr.Code != http.StatusFound { t.Errorf("Expected Redirect 302, got %d", rr.Code) }
	})

	t.Run("LOGIN: Success", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"email": "test@example.com", "password": "Password123!"}`))
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("LOGIN: Fail Wrong Password", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"email": "test@example.com", "password": "WrongPassword!"}`))
		rr := execute(req)
		if rr.Code != http.StatusUnauthorized { t.Errorf("Expected 401, got %d", rr.Code) }
	})

	t.Run("LOGIN: Fail Not Found Email", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"email": "notfound@example.com", "password": "Password123!"}`))
		rr := execute(req)
		if rr.Code != http.StatusUnauthorized { t.Errorf("Expected 401, got %d", rr.Code) }
	})

	// ==========================================
	// 2. USER PROFILE TESTS
	// ==========================================
	t.Run("USER: Get Me", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("USER: Update Me", func(t *testing.T) {
		req, _ := http.NewRequest("PUT", "/api/users/me", strings.NewReader(`{"username": "NewName"}`))
		req.Header.Set("Authorization", "Bearer "+userToken)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("USER: Delete Me", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", "/api/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("USER: Avatar Upload Success", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="avatar"; filename="test.jpg"`)
		h.Set("Content-Type", "image/jpeg")
		part, _ := writer.CreatePart(h)
		part.Write([]byte("fake image data"))
		writer.Close()

		req, _ := http.NewRequest("POST", "/api/users/me/avatar", body)
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("USER: Avatar Upload Fail (Text file)", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="avatar"; filename="test.txt"`)
		h.Set("Content-Type", "text/plain")
		part, _ := writer.CreatePart(h)
		part.Write([]byte("malicious script"))
		writer.Close()

		req, _ := http.NewRequest("POST", "/api/users/me/avatar", body)
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		rr := execute(req)
		if rr.Code != http.StatusBadRequest { t.Errorf("Expected 400 for bad file type, got %d", rr.Code) }
	})

	// ==========================================
	// 3. ADMIN TESTS
	// ==========================================
	t.Run("ADMIN: List Users", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("ADMIN: Update User Role", func(t *testing.T) {
		req, _ := http.NewRequest("PUT", "/api/admin/users/1", strings.NewReader(`{"role": "admin"}`))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("ADMIN: Add Carousel", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("title", "New Slide")
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="image"; filename="test.jpg"`)
		h.Set("Content-Type", "image/jpeg")
		part, _ := writer.CreatePart(h)
		part.Write([]byte("img"))
		writer.Close()

		req, _ := http.NewRequest("POST", "/api/admin/carousel", body)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("ADMIN: Delete Carousel", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", "/api/admin/carousel/1", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rr := execute(req)
		if rr.Code != http.StatusNoContent { t.Errorf("Expected 204, got %d", rr.Code) }
	})

	t.Run("ADMIN: Update Homepage", func(t *testing.T) {
		req, _ := http.NewRequest("PUT", "/api/admin/homepage", strings.NewReader(`{"section_name": "hero", "content": "Welcome!"}`))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	// ==========================================
	// 4. GUEST & SYSTEM TESTS
	// ==========================================
	t.Run("GUEST: Get Carousel", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/carousel", nil)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("GUEST: Get Homepage", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/homepage", nil)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("GUEST: Logout", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/logout", nil)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("SYS: Healthz", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/health", nil)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("SYS: Unknown Route 404", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/unknown_route_xyz", nil)
		rr := execute(req)
		if rr.Code != http.StatusNotFound { t.Errorf("Expected 404, got %d", rr.Code) }
	})
	
	t.Run("SYS: Download Windows", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/download/windows", nil)
		rr := execute(req)
		if rr.Code == http.StatusNotFound { t.Errorf("Route /api/download/windows should exist") }
	})
}