package main

import (
  "context"
  "log"
  "net/http"
  "os"
  "os/signal"
  "syscall"
  "time"

  "projectgob-backend/internal/config"
  "projectgob-backend/internal/httpapi"
)

func main() {
  cfg := config.Load()

  srv := &http.Server{
    Addr:              ":" + cfg.Port,
    Handler:           httpapi.NewRouter(cfg),
    ReadHeaderTimeout: 15 * time.Second,
    ReadTimeout:       30 * time.Second,
    WriteTimeout:      30 * time.Second,
    IdleTimeout:       90 * time.Second,
  }

  // Graceful shutdown
  stop := make(chan os.Signal, 1)
  signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

  go func() {
    log.Printf("[backend] listening on :%s (env=%s)\n", cfg.Port, cfg.NodeEnv)
    if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
      log.Fatalf("listen error: %v", err)
    }
  }()

  <-stop
  log.Println("[backend] shutting down...")

  ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
  defer cancel()
  _ = srv.Shutdown(ctx)
}
