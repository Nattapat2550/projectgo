package httpapi

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type keyFunc func(r *http.Request) (string, error)

// GetClientIP ทำหน้าที่เทียบเท่า trust proxy ของ Express
// เพื่อดึง IP จริงในกรณีที่รันอยู่หลัง Reverse Proxy (เช่น Render, Nginx)
func GetClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	
	// Fallback ไปที่ RemoteAddr (ตัดส่วนพอร์ตออก)
	ip := r.RemoteAddr
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		ip = ip[:colonIdx]
	}
	return ip
}

// rateLimit is a tiny per-IP fixed-window rate limiter.
func rateLimit(max int, window time.Duration, key keyFunc) func(http.Handler) http.Handler {
	type bucket struct {
		windowStart time.Time
		count       int
		lastSeen    time.Time
	}

	var (
		mu      sync.Mutex
		buckets = make(map[string]*bucket)
	)

	// Cleanup goroutine (best effort)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-2 * window)
			mu.Lock()
			for k, b := range buckets {
				if b.lastSeen.Before(cutoff) {
					delete(buckets, k)
				}
			}
			mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			k, err := key(r)
			if err != nil || k == "" {
				k = "unknown"
			}

			now := time.Now()

			mu.Lock()
			b := buckets[k]
			if b == nil {
				b = &bucket{windowStart: now, count: 0, lastSeen: now}
				buckets[k] = b
			}
			// reset window
			if now.Sub(b.windowStart) >= window {
				b.windowStart = now
				b.count = 0
			}
			b.count++
			b.lastSeen = now
			count := b.count
			resetIn := window - now.Sub(b.windowStart)
			mu.Unlock()

			// Informative headers (similar to modern rate limit middlewares)
			w.Header().Set("RateLimit-Limit", itoa(max))
			w.Header().Set("RateLimit-Remaining", itoa(max-count))
			w.Header().Set("RateLimit-Reset", itoa(int(resetIn.Seconds())))

			if count > max {
				w.Header().Set("Retry-After", itoa(int(resetIn.Seconds())))
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte("Too many requests. Please try again later."))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [32]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + (n % 10))
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}