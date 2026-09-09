// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package planted is a deliberately vulnerable fixture for the security-review
// scanner profiles (Issue #3982). It is never compiled into CFGMS: it lives in
// its own module under a dot-directory, outside the root module's `./...`.
// Each function below plants exactly one finding a specific tool in the Go
// profile must recover; `lanes/scan_fixtures_test.py` asserts that it does,
// so an emptied profile or a broken rule fails the test instead of passing
// silently. No suppression comments -- a `#nosec` here would defeat the test.
package planted

import (
	"crypto/md5"
	"fmt"
	"log/slog"
	"strings"
)

// HashPassword plants gosec G401/G501 (weak crypto primitive and import) and
// the upstream semgrep taint rule go.lang.security.audit.md5-used-as-password
// (an md5 digest flowing into a function whose name contains "password").
func HashPassword(password string) string {
	sum := md5.Sum([]byte(password))
	storePassword(sum)
	return fmt.Sprintf("%x", sum)
}

func storePassword(digest [16]byte) {
	_ = digest
}

// LogFailure plants the CFGMS semgrep rule cfgms-raw-error-in-structured-log:
// a raw error under the "error" key. Neither gosec nor staticcheck reports
// this -- it is the fixture that proves the project rules add coverage.
func LogFailure(logger *slog.Logger, err error) {
	logger.Error("store unreachable", "error", err)
}

// Discarded plants staticcheck SA4017 (result of a pure function discarded).
func Discarded(name string) {
	strings.ToUpper(name)
}
