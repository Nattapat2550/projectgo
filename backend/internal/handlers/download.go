package handlers

import (
  "io"
  "net/http"
  "strings"
)

func (h *Handler) DownloadWindows(w http.ResponseWriter, r *http.Request) {
  h.proxyDownload(w, r, "/api/download/windows", "MyAppSetup.exe")
}

func (h *Handler) DownloadAndroid(w http.ResponseWriter, r *http.Request) {
  h.proxyDownload(w, r, "/api/download/android", "app-release.apk")
}

func (h *Handler) proxyDownload(w http.ResponseWriter, r *http.Request, purePath string, fallbackFilename string) {
  base := strings.TrimRight(strings.TrimSpace(h.Cfg.PureAPIBaseURL), "/")
  if base == "" || strings.TrimSpace(h.Cfg.PureAPIKey) == "" {
    h.writeError(w, http.StatusInternalServerError, "Pure API is not configured")
    return
  }

  upstreamURL := base + "/" + strings.TrimLeft(purePath, "/")
  req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL, nil)
  req.Header.Set("x-api-key", h.Cfg.PureAPIKey)

  resp, err := http.DefaultClient.Do(req)
  if err != nil {
    h.writeError(w, http.StatusBadGateway, "Download failed")
    return
  }
  defer resp.Body.Close()

  if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
    h.writeError(w, resp.StatusCode, "Pure API download failed: "+string(b))
    return
  }

  // forward relevant headers
  if ct := resp.Header.Get("Content-Type"); ct != "" {
    w.Header().Set("Content-Type", ct)
  }
  if cl := resp.Header.Get("Content-Length"); cl != "" {
    w.Header().Set("Content-Length", cl)
  }
  if cd := resp.Header.Get("Content-Disposition"); cd != "" {
    w.Header().Set("Content-Disposition", cd)
  } else {
    w.Header().Set("Content-Disposition", "attachment; filename=\""+fallbackFilename+"\"")
  }

  w.WriteHeader(http.StatusOK)
  _, _ = io.Copy(w, resp.Body)
}
