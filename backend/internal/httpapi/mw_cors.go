package httpapi

import (
  "net/http"
  "strings"
)

// cors mimics the old Express cors({ origin: FRONTEND_URL, credentials:true }).
// - Allows credentials
// - Echoes Origin only if it matches allowed list
// - Handles preflight OPTIONS
func cors(allowedOrigins []string) func(http.Handler) http.Handler {
  allow := make(map[string]struct{}, len(allowedOrigins))
  for _, o := range allowedOrigins {
    o = strings.TrimSpace(o)
    if o != "" {
      allow[o] = struct{}{}
    }
  }

  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      origin := r.Header.Get("Origin")
      if origin != "" {
        if _, ok := allow[origin]; ok {
          w.Header().Set("Access-Control-Allow-Origin", origin)
          w.Header().Set("Vary", "Origin")
          w.Header().Set("Access-Control-Allow-Credentials", "true")
          w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
          w.Header().Set("Access-Control-Allow-Headers", "Accept,Authorization,Content-Type,X-API-Key")
          w.Header().Set("Access-Control-Expose-Headers", "Content-Length,Content-Type,Content-Disposition")
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
