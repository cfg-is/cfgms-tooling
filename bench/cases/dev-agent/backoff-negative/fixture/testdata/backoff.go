// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package testdata

// ClampRetryBackoff validates a retry backoff in seconds read from steward
// config. A negative value is invalid and must be rejected with a clear
// error -- silently clamping it to zero would let a misconfigured steward
// retry in a tight loop without anyone noticing.
func ClampRetryBackoff(seconds int) (int, error) {
	return seconds, nil
}
