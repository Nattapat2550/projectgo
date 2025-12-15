package httpapi

import (
  "net/http"
  "sync"
  "time"
)

type keyFunc func(r *http.Request) (string, error)

// rateLimit is a tiny per-IP fixed-window rate limiter.
// It avoids external deps while matching the old Express rate limit config:
// window = 15min, max = 400 requests per key.
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
        _, _ = w.Write([]byte("Too many requests"))
        return
      }

      next.ServeHTTP(w, r)
    })
  }
}

func itoa(n int) string {
  // small int->string helper to avoid fmt on hot path
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
