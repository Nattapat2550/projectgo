package handlers

import "net/http"

// POST /api/admin/users/update
// Body: { id: <userId>, ...fields }
// This proxies to pure-api internal admin update.
func (h *Handler) AdminUsersUpdate(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  var payload map[string]any
  if err := ReadJSON(r, &payload); err != nil {
    h.writeError(w, http.StatusBadRequest, "Invalid JSON")
    return
  }
  if payload == nil || payload["id"] == nil {
    h.writeError(w, http.StatusBadRequest, "Missing user id")
    return
  }
  var resp any
  if err := h.Pure.Post(ctx, "/api/internal/admin/users/update", payload, &resp); err != nil {
    h.writeErrFrom(w, err)
    return
  }
  WriteJSON(w, http.StatusOK, resp)
}
