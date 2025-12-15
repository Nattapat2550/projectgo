package handlers

import (
  "encoding/base64"
  "io"
  "net/http"
  "strings"

  "projectgob-backend/internal/pureapi"
)

func (h *Handler) UsersMeGet(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  u := GetUser(r)
  var resp okData[userDTO]
  if err := h.Pure.Post(ctx, "/api/internal/find-user", map[string]any{"id": u.ID}, &resp); err != nil {
    h.writeErrFrom(w, err)
    return
  }
  if !resp.Ok || resp.Data == nil {
    h.writeError(w, http.StatusNotFound, "Not found")
    return
  }

  out := map[string]any{
    "id":                  resp.Data.ID,
    "username":            deref(resp.Data.Username),
    "email":               resp.Data.Email,
    "role":                resp.Data.Role,
    "profile_picture_url": deref(resp.Data.ProfilePictureURL),
  }
  WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) UsersMePut(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  u := GetUser(r)

  var in struct {
    Username          *string `json:"username"`
    ProfilePictureUrl *string `json:"profilePictureUrl"`
  }
  if err := ReadJSON(r, &in); err != nil {
    h.writeError(w, http.StatusBadRequest, "Invalid JSON")
    return
  }

  payload := map[string]any{
    "id":                  u.ID,
    "username":            nilOrString(in.Username),
    "profile_picture_url": nilOrString(in.ProfilePictureUrl),
  }
  var resp okData[userDTO]
  if err := h.Pure.Post(ctx, "/api/internal/admin/users/update", payload, &resp); err != nil {
    // best-effort: map username conflict
    if pe, ok := err.(*pureapi.Error); ok && pe.Status == 409 {
      h.writeError(w, http.StatusConflict, "Username already taken")
      return
    }
    h.writeErrFrom(w, err)
    return
  }
  if !resp.Ok || resp.Data == nil {
    h.writeError(w, http.StatusNotFound, "Not found")
    return
  }
  WriteJSON(w, http.StatusOK, map[string]any{
    "id":                  resp.Data.ID,
    "username":            deref(resp.Data.Username),
    "email":               resp.Data.Email,
    "role":                resp.Data.Role,
    "profile_picture_url": deref(resp.Data.ProfilePictureURL),
  })
}

func (h *Handler) UsersMeDelete(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  u := GetUser(r)

  if err := h.Pure.Post(ctx, "/api/internal/delete-user", map[string]any{"id": u.ID}, nil); err != nil {
    h.writeErrFrom(w, err)
    return
  }
  h.clearAuthCookie(w)
  w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UsersMeAvatar(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  u := GetUser(r)

  // 2MB limit
  r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
  if err := r.ParseMultipartForm(2 * 1024 * 1024); err != nil {
    h.writeError(w, http.StatusBadRequest, "No file")
    return
  }
  f, hdr, err := r.FormFile("avatar")
  if err != nil {
    h.writeError(w, http.StatusBadRequest, "No file")
    return
  }
  defer f.Close()

  mime := hdr.Header.Get("Content-Type")
  if mime == "" {
    // sniff
    buf := make([]byte, 512)
    n, _ := f.Read(buf)
    mime = http.DetectContentType(buf[:n])
    _, _ = f.Seek(0, io.SeekStart)
  }
  if !strings.HasPrefix(mime, "image/") {
    h.writeError(w, http.StatusBadRequest, "Unsupported file type")
    return
  }
  okType := mime == "image/png" || mime == "image/jpeg" || mime == "image/gif" || mime == "image/webp"
  if !okType {
    h.writeError(w, http.StatusBadRequest, "Unsupported file type")
    return
  }

  data, err := io.ReadAll(f)
  if err != nil {
    h.writeError(w, http.StatusInternalServerError, "Upload failed")
    return
  }
  b64 := base64.StdEncoding.EncodeToString(data)
  dataURL := "data:" + mime + ";base64," + b64

  var resp okData[userDTO]
  if err := h.Pure.Post(ctx, "/api/internal/admin/users/update", map[string]any{
    "id":                  u.ID,
    "username":            nil,
    "profile_picture_url": dataURL,
  }, &resp); err != nil {
    h.writeErrFrom(w, err)
    return
  }
  if !resp.Ok || resp.Data == nil {
    h.writeError(w, http.StatusNotFound, "Not found")
    return
  }
  WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "profile_picture_url": deref(resp.Data.ProfilePictureURL)})
}

func nilOrString(s *string) any {
  if s == nil {
    return nil
  }
  v := strings.TrimSpace(*s)
  if v == "" {
    return nil
  }
  return v
}

func deref(s *string) any {
  if s == nil {
    return nil
  }
  return *s
}
