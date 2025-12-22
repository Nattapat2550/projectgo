package httpapi

import (
  "net/http"
  "strings"
)

func cors(allowedOrigins []string, isProd bool) func(http.Handler) http.Handler {
  allow := make(map[string]struct{}, len(allowedOrigins))
  for _, o := range allowedOrigins {
    o = strings.TrimSpace(o)
    if o != "" {
      allow[o] = struct{}{}
    }
  }

  allowAll := !isProd || len(allow) == 0

  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      origin := r.Header.Get("Origin")
      if origin != "" {
        if allowAll {
          w.Header().Set("Access-Control-Allow-Origin", origin)
        } else {
          if _, ok := allow[origin]; ok {
            w.Header().Set("Access-Control-Allow-Origin", origin)
          }
        }

        if w.Header().Get("Access-Control-Allow-Origin") != "" {
          w.Header().Set("Vary", "Origin")
          w.Header().Set("Access-Control-Allow-Credentials", "true")
          w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
          w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,x-requested-with,X-API-Key")
          w.Header().Set("Access-Control-Expose-Headers", "Content-Length,Content-Type,Content-Disposition")
        }
      }

      if r.Method == http.MethodOptions {
        w.WriteHeader(http.StatusNoContent)
        return
      }

      next.ServeHTTP(w, r)
    })
  }
}
