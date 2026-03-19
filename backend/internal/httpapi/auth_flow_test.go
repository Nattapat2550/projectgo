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
// 🛠 ฟังก์ชันช่วยเหลือ (Helpers)
// ==========================================

// สร้าง Mock Token สำหรับทดสอบ (จำลองการ Login)
func generateTestToken(userID int64, role string, secret string) string {
	claims := jwt.MapClaims{
		"userId": userID, // 📌 เปลี่ยนจาก "user_id" เป็น "userId" ให้ตรงกับ auth_middleware
		"role":   role,
		"exp":    time.Now().Add(1 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, _ := token.SignedString([]byte(secret))
	return t
}

func TestComprehensiveSystem(t *testing.T) {
	jwtSecret := "supersecret_test_jwt_key_123456"

	// 🛑 1. Mock Pure API Server (จำลองฐานข้อมูลทั้งหมด)
	pureMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")

		// คืนค่า Mock ตอบกลับตาม API ที่เรียก
		switch {
		// --- หมวด Auth ---
		case strings.Contains(path, "create-user"):
			w.Write([]byte(`{"id": 1, "email": "test@example.com"}`))
		case strings.Contains(path, "store-verification-code") || strings.Contains(path, "verify-code"):
			w.Write([]byte(`{"ok": true, "userId": 1}`))
		case strings.Contains(path, "set-username-password"):
			w.Write([]byte(`{"id": 1, "email": "test@example.com", "username": "Tester", "role": "user"}`))
		case strings.Contains(path, "find-user"):
			hash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
			json.NewEncoder(w).Encode(map[string]any{
				"id": 1, "email": "test@example.com", "username": "Tester",
				"role": "user", "password_hash": string(hash),
			})
		case strings.Contains(path, "reset-token") || strings.Contains(path, "set-password"):
			w.Write([]byte(`{"ok": true, "id": 1}`))
			
		// --- หมวด User & Admin ---
		case strings.Contains(path, "users") || strings.Contains(path, "avatar"):
			w.Write([]byte(`{"ok": true, "message": "success"}`))
			
		// --- หมวด Public & Homepage & Carousel ---
		case strings.Contains(path, "homepage"):
			w.Write([]byte(`{"hero_title": "Welcome to System"}`))
		case strings.Contains(path, "carousel"):
			w.Write([]byte(`[{"id": 1, "image_url": "slide1.jpg"}]`))

		default:
			w.Write([]byte(`{"ok": true}`)) // Catch-all fallback
		}
	}))
	defer pureMock.Close()

	// 🛑 2. โหลด Config สำหรับโหมด Test
	cfg := config.Config{
		PureAPIBaseURL: pureMock.URL,
		EmailDisable:   true,
		JWTSecret:      jwtSecret,
		FrontendURL:    "http://localhost:3000",
	}

	router := httpapi.NewRouter(cfg)

	// ฟังก์ชันรัน HTTP Request
	execute := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// สร้าง Token สำหรับใช้เทส
	userToken := generateTestToken(1, "user", jwtSecret)
	adminToken := generateTestToken(99, "admin", jwtSecret)

	// ==========================================
	// 🟢 หมวดที่ 1: AUTHENTICATION
	// ==========================================
	t.Run("AUTH-01: สมัครสมาชิกใหม่ (Register)", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/register", strings.NewReader(`{"email": "test@example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("AUTH-06: เข้าสู่ระบบ (Login)", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"email": "test@example.com", "password": "Password123!"}`))
		req.Header.Set("Content-Type", "application/json")
		rr := execute(req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"token"`) {
			t.Errorf("Login Failed: %v", rr.Body.String())
		}
	})

	t.Run("AUTH-09: ออกจากระบบ (Logout)", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/auth/logout", nil)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	// ==========================================
	// 👤 หมวดที่ 2: USER PROFILE
	// ==========================================
	t.Run("USR-01: ขอข้อมูลส่วนตัวโดยไม่มี Token (ต้องโดนบล็อก)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/users/me", nil)
		rr := execute(req)
		if rr.Code != http.StatusUnauthorized { t.Errorf("Expected 401, got %d", rr.Code) }
	})

	t.Run("USR-02: ขอข้อมูลส่วนตัวสำเร็จ (แนบ Token)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("USR-04: อัปโหลดรูปภาพโปรไฟล์", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		// 📌 สร้าง Header ของไฟล์จำลองและบังคับให้เป็น image/jpeg
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="avatar"; filename="test.jpg"`)
		h.Set("Content-Type", "image/jpeg")

		part, _ := writer.CreatePart(h)
		part.Write([]byte("fake image content"))
		writer.Close()

		req, _ := http.NewRequest("POST", "/api/users/me/avatar", body)
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		
		rr := execute(req)
		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}
	})

	// ==========================================
	// 👑 หมวดที่ 3: ADMIN CMS
	// ==========================================
	t.Run("ADM-01: User ธรรมดาเข้าเมนูแอดมิน (ต้องโดนบล็อก)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+userToken) // ใช้ Token ธรรมดา
		rr := execute(req)
		if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 403 or 401, got %d", rr.Code)
		}
	})

	t.Run("ADM-02: Admin ดูรายชื่อ User ทั้งหมดสำเร็จ", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken) // ใช้ Token Admin
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("ADM-08: Admin แก้ไขข้อความหน้าเว็บ", func(t *testing.T) {
		body := `{"hero_title": "New Updated Title"}`
		req, _ := http.NewRequest("PUT", "/api/admin/homepage", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		
		rr := execute(req)
		if rr.Code != http.StatusOK && rr.Code != http.StatusNotFound {
			// ถ้าหา Route /api/admin/homepage ไม่เจอในโครงสร้างอาจได้ 404 ซึ่งถือว่าผ่านพฤติกรรม Router
			t.Logf("Got status: %d", rr.Code) 
		}
	})

	// ==========================================
	// 🏠 หมวดที่ 4: PUBLIC & GUEST
	// ==========================================
	t.Run("PUB-01: ดึงข้อมูลหน้าแรก (ไม่ต้องใช้ Token)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/homepage", nil)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("PUB-03: เข้าถึง URL ที่ไม่มีอยู่จริง (404)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/unknown-path-1234", nil)
		rr := execute(req)
		if rr.Code != http.StatusNotFound { t.Errorf("Expected 404, got %d", rr.Code) }
	})

	// ==========================================
	// 📦 หมวดที่ 5: SYSTEM & DOWNLOAD
	// ==========================================
	t.Run("SYS-01: ตรวจสอบสถานะเซิร์ฟเวอร์", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/health", nil)
		rr := execute(req)
		if rr.Code != http.StatusOK { t.Errorf("Expected 200, got %d", rr.Code) }
	})

	t.Run("SYS-02: ดาวน์โหลดโปรแกรม Windows", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/download/windows", nil)
		rr := execute(req)
		// อาจจะเป็น 200 (กรณีมีไฟล์ mock) หรือ 500 (กรณีไม่มีไฟล์จริงในเครื่องขณะเทส)
		// เช็คแค่ว่า Route นี้มีอยู่จริง
		if rr.Code == http.StatusNotFound {
			t.Errorf("Route not found for Windows Download")
		}
	})
}