package handlers

import "net/http"

// GET /api/carousel
func (h *Handler) CarouselList(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  // pure-api may return {ok:true,data:[...]}, so try unwrap; otherwise pass-through
  var wrapped struct {
    Ok   bool `json:"ok"`
    Data any  `json:"data"`
  }
  if err := h.Pure.Get(ctx, "/api/internal/carousel/items", &wrapped); err != nil {
    h.writeErrFrom(w, err)
    return
  }
  if wrapped.Ok {
    WriteJSON(w, http.StatusOK, wrapped.Data)
    return
  }
  // fallback
  WriteJSON(w, http.StatusOK, wrapped)
}
