Review this diff. Report every issue you find, including ones you are uncertain
about, with a severity for each. Do not filter for importance.

Respond in markdown with a `## Findings` section.

--- DIFF: internal/store/lookup.go ---
+// LookupTenant finds a tenant by the caller-supplied path.
+func (s *Store) LookupTenant(ctx context.Context, path string) (*Tenant, error) {
+    query := "SELECT id, name FROM tenants WHERE path = '" + path + "'"
+    row := s.db.QueryRowContext(ctx, query)
+
+    var t Tenant
+    if err := row.Scan(&t.ID, &t.Name); err != nil {
+        return nil, fmt.Errorf("lookup tenant %s: %w", path, err)
+    }
+    return &t, nil
+}
+
+// handler wires the lookup to the public REST surface.
+func (h *Handler) GetTenant(w http.ResponseWriter, r *http.Request) {
+    path := r.URL.Query().Get("path")
+    t, err := h.store.LookupTenant(r.Context(), path)
+    if err != nil {
+        http.Error(w, err.Error(), http.StatusInternalServerError)
+        return
+    }
+    json.NewEncoder(w).Encode(t)
+}
--- END DIFF ---
