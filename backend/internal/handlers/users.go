package handlers

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GET /api/users/me
func (h *Handler) UsersMeGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := GetUser(r)
	if u == nil {
		h.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var me userDTO
	if err := h.Pure.Post(ctx, "/api/internal/find-user", map[string]any{"id": u.ID}, &me); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, me)
}

// PUT /api/users/me
func (h *Handler) UsersMePut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := GetUser(r)
	if u == nil {
		h.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var body map[string]any
	if err := ReadJSON(r, &body); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	payload := map[string]any{"id": u.ID}
	for k, v := range body {
		payload[k] = v
	}

	var updated userDTO
	if err := h.Pure.Post(ctx, "/api/internal/admin/users/update", payload, &updated); err != nil {
		if isUsernameUniqueViolation(err) {
			h.writeError(w, http.StatusConflict, "Username already taken")
			return
		}
		h.writeErrFrom(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, updated)
}

// POST /api/users/me/avatar (multipart: avatar)
func (h *Handler) UsersMeAvatar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := GetUser(r)
	if u == nil {
		h.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// 4MB limit (match Node)
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
	if err := r.ParseMultipartForm(4 * 1024 * 1024); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid form")
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "No file")
		return
	}
	defer file.Close()

	mime := strings.ToLower(strings.TrimSpace(header.Header.Get("Content-Type")))
	if !strings.HasPrefix(mime, "image/") || !allowedImageMime(mime) {
		h.writeError(w, http.StatusBadRequest, "Invalid file type")
		return
	}

	b, err := io.ReadAll(file)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Read failed")
		return
	}
	if int64(len(b)) > 4*1024*1024 {
		h.writeError(w, http.StatusBadRequest, "File too large")
		return
	}

	dataURL := fmt.Sprintf("data:%s;base64,%s", mime, base64.StdEncoding.EncodeToString(b))

	payload := map[string]any{
		"id":                  u.ID,
		"profile_picture_url": dataURL,
	}

	var updated userDTO
	if err := h.Pure.Post(ctx, "/api/internal/admin/users/update", payload, &updated); err != nil {
		h.writeErrFrom(w, err)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"ok":                  true,
		"profile_picture_url": updated.ProfilePictureURL,
	})
}

// DELETE /api/users/me
func (h *Handler) UsersMeDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := GetUser(r)
	if u == nil {
		h.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if err := h.Pure.Post(ctx, "/api/internal/delete-user", map[string]any{"id": u.ID}, nil); err != nil {
		h.writeErrFrom(w, err)
		return
	}

	h.clearAuthCookie(w)
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
