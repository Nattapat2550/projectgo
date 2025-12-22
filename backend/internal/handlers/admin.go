package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"projectgob-backend/internal/pureapi"
)

// ---------- Admin: Users ----------

// GET /api/admin/users
func (h *Handler) AdminUsersList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var users any
	if err := h.Pure.Get(ctx, "/api/internal/admin/users", &users); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, users)
}

// PUT /api/admin/users/{id}
func (h *Handler) AdminUsersUpdateByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		h.writeError(w, http.StatusBadRequest, "Invalid user id")
		return
	}

	var body map[string]any
	if err := ReadJSON(r, &body); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// pure-api internal endpoint: POST /api/internal/admin/users/update
	payload := map[string]any{"id": id}
	for k, v := range body {
		payload[k] = v
	}

	var updated any
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

// POST /api/admin/users/update (legacy path kept for compatibility)
func (h *Handler) AdminUsersUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var payload map[string]any
	if err := ReadJSON(r, &payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	var updated any
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

// ---------- Admin: Carousel ----------

// GET /api/admin/carousel
func (h *Handler) AdminCarouselList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var items any
	if err := h.Pure.Get(ctx, "/api/internal/carousel/list", &items); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, items)
}

// POST /api/admin/carousel (multipart: image + fields)
func (h *Handler) AdminCarouselCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 4MB limit (match Node)
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
	if err := r.ParseMultipartForm(4 * 1024 * 1024); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid form")
		return
	}

	dataURL, err := readImageDataURL(r, "image", 4*1024*1024)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	payload := map[string]any{
		"title":        strings.TrimSpace(r.FormValue("title")),
		"subtitle":     strings.TrimSpace(r.FormValue("subtitle")),
		"description":  strings.TrimSpace(r.FormValue("description")),
		"link":         strings.TrimSpace(r.FormValue("link")),
		"imageDataUrl": dataURL,
	}

	// itemIndex is optional
	if v := strings.TrimSpace(r.FormValue("itemIndex")); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			payload["itemIndex"] = n
		}
	} else if v := strings.TrimSpace(r.FormValue("item_index")); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			payload["item_index"] = n
		}
	}

	var created any
	if err := h.Pure.Post(ctx, "/api/internal/carousel/create", payload, &created); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, created)
}

// PUT /api/admin/carousel/{id} (multipart, image optional)
func (h *Handler) AdminCarouselUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		h.writeError(w, http.StatusBadRequest, "Invalid carousel id")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
	if err := r.ParseMultipartForm(4 * 1024 * 1024); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid form")
		return
	}

	payload := map[string]any{
		"id":          id,
		"title":       strings.TrimSpace(r.FormValue("title")),
		"subtitle":    strings.TrimSpace(r.FormValue("subtitle")),
		"description": strings.TrimSpace(r.FormValue("description")),
		"link":        strings.TrimSpace(r.FormValue("link")),
	}

	// itemIndex optional
	if v := strings.TrimSpace(r.FormValue("itemIndex")); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			payload["itemIndex"] = n
		}
	} else if v := strings.TrimSpace(r.FormValue("item_index")); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			payload["item_index"] = n
		}
	}

	// image optional
	if dataURL, e := tryReadImageDataURL(r, "image", 4*1024*1024); e != nil {
		h.writeError(w, http.StatusBadRequest, e.Error())
		return
	} else if dataURL != "" {
		payload["imageDataUrl"] = dataURL
	}

	var updated any
	if err := h.Pure.Post(ctx, "/api/internal/carousel/update", payload, &updated); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, updated)
}

// DELETE /api/admin/carousel/{id}
func (h *Handler) AdminCarouselDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		h.writeError(w, http.StatusBadRequest, "Invalid carousel id")
		return
	}

	payload := map[string]any{"id": id}
	if err := h.Pure.Post(ctx, "/api/internal/carousel/delete", payload, nil); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- helpers ----------

func isUsernameUniqueViolation(err error) bool {
	var pe *pureapi.Error
	if !errors.As(err, &pe) {
		return false
	}
	m, ok := pe.Detail.(map[string]any)
	if !ok {
		return false
	}
	eo, ok := m["error"].(map[string]any)
	if !ok {
		return false
	}
	d, _ := eo["details"].(string)
	d = strings.ToLower(d)
	return strings.Contains(d, "duplicate key") && strings.Contains(d, "users_username_key")
}

func readImageDataURL(r *http.Request, field string, maxBytes int64) (string, error) {
	f, hdr, err := r.FormFile(field)
	if err != nil {
		return "", fmt.Errorf("No image")
	}
	defer f.Close()

	mime := hdr.Header.Get("Content-Type")
	if mime == "" {
		mime = hdr.Header.Get("content-type")
	}
	mime = strings.ToLower(strings.TrimSpace(mime))
	if !strings.HasPrefix(mime, "image/") {
		return "", fmt.Errorf("Unsupported file type")
	}
	if !allowedImageMime(mime) {
		return "", fmt.Errorf("Unsupported file type")
	}

	b, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("Read failed")
	}
	if int64(len(b)) > maxBytes {
		return "", fmt.Errorf("File too large")
	}
	enc := base64.StdEncoding.EncodeToString(b)
	return fmt.Sprintf("data:%s;base64,%s", mime, enc), nil
}

func tryReadImageDataURL(r *http.Request, field string, maxBytes int64) (string, error) {
	f, hdr, err := r.FormFile(field)
	if err != nil {
		// no file provided
		return "", nil
	}
	defer f.Close()

	mime := hdr.Header.Get("Content-Type")
	if mime == "" {
		mime = hdr.Header.Get("content-type")
	}
	mime = strings.ToLower(strings.TrimSpace(mime))
	if !strings.HasPrefix(mime, "image/") {
		return "", fmt.Errorf("Unsupported file type")
	}
	if !allowedImageMime(mime) {
		return "", fmt.Errorf("Unsupported file type")
	}

	b, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("Read failed")
	}
	if int64(len(b)) > maxBytes {
		return "", fmt.Errorf("File too large")
	}
	enc := base64.StdEncoding.EncodeToString(b)
	return fmt.Sprintf("data:%s;base64,%s", mime, enc), nil
}

func allowedImageMime(m string) bool {
	switch m {
	case "image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp":
		return true
	default:
		return false
	}
}
