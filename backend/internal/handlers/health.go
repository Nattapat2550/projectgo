package handlers

import "net/http"

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
  WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
