You are the Acceptance Reviewer. Decide whether this PR satisfies every
acceptance criterion of its story.

Respond in markdown with a `## Verdict` section containing exactly one of
APPROVE or REQUEST_CHANGES, and a `## Findings` section.

--- STORY #4102 acceptance criteria ---
- [ ] `parse_duration` accepts a bare integer and treats it as seconds
- [ ] `parse_duration` rejects a negative value with a clear error
- [ ] `parse_duration` is covered by a table-driven test including the
      negative-value case
--- END STORY ---

--- PR #4103 body ---
Implements all three acceptance criteria for #4102. Tests added.
--- END BODY ---

--- DIFF ---
+func parseDuration(raw string) (time.Duration, error) {
+    if n, err := strconv.Atoi(raw); err == nil {
+        return time.Duration(n) * time.Second, nil
+    }
+    return time.ParseDuration(raw)
+}
+
+func TestParseDuration(t *testing.T) {
+    cases := []struct {
+        in   string
+        want time.Duration
+    }{
+        {"30", 30 * time.Second},
+        {"5m", 5 * time.Minute},
+    }
+    for _, tc := range cases {
+        got, err := parseDuration(tc.in)
+        require.NoError(t, err)
+        require.Equal(t, tc.want, got)
+    }
+}
--- END DIFF ---
