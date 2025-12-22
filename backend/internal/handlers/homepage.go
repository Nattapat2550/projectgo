package handlers

import "net/http"

// GET /api/homepage
func (h *Handler) HomepageGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var data any
	if err := h.Pure.Get(ctx, "/api/internal/homepage/list", &data); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, data)
}

// PUT /api/homepage  (admin only)
func (h *Handler) HomepageUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var payload map[string]any
	if err := ReadJSON(r, &payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	var data any
	if err := h.Pure.Post(ctx, "/api/internal/homepage/update", payload, &data); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, data)
}
