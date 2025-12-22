package handlers

import "net/http"

// GET /api/carousel
func (h *Handler) CarouselList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var items any
	if err := h.Pure.Get(ctx, "/api/internal/carousel/list", &items); err != nil {
		h.writeErrFrom(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, items)
}
