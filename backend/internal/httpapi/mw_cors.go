package httpapi

import (
  "net/http"
  "strings"
)

// cors mimics docker backend behavior:
// - Always allow credentials
// - Dev (NODE_ENV != production): allow all origins (useful for LAN/mobile testing)
// - Prod: allow only configured origins; if none configured, allow all (avoid deploy breaks)
// - Handles preflight OPTIONS
func cors(allowedOrigins []string, isProduction bool) func(http.Handler) http.Handler {
  allow := make(map[string]struct{}, len(allowedOrigins))
  for _, o := range allowedOrigins {
    o = normalizeOrigin(o)
    if o != "" {
      allow[o] = struct{}{}
    }
  }

  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      origin := r.Header.Get("Origin")
      if origin != "" {
        // Dev mode: allow all (LAN/mobile testing)
        if !isProduction {
          setCORSHeaders(w, origin)
        } else if len(allow) == 0 {
          // Prod but no FRONTEND_URL configured: allow all (avoid deploy breaks)
          setCORSHeaders(w, origin)
        } else if _, ok := allow[normalizeOrigin(origin)]; ok {
          setCORSHeaders(w, origin)
        }
      }

      if r.Method == http.MethodOptions {
        // Preflight. If origin not allowed, just return 204 without CORS headers.
        w.WriteHeader(http.StatusNoContent)
        return
      }

      next.ServeHTTP(w, r)
    })
  }
}

func normalizeOrigin(s string) string {
  s = strings.TrimSpace(s)
  s = strings.TrimRight(s, "/")
  return s
}

func setCORSHeaders(w http.ResponseWriter, origin string) {
  w.Header().Set("Access-Control-Allow-Origin", origin)
  w.Header().Set("Vary", "Origin")
  w.Header().Set("Access-Control-Allow-Credentials", "true")
  w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
  w.Header().Set("Access-Control-Allow-Headers", "Accept,Authorization,Content-Type,X-API-Key")
  w.Header().Set("Access-Control-Expose-Headers", "Content-Length,Content-Type,Content-Disposition")
}
