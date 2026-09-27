// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Deliberately vulnerable fixture for the security-review TS/TSX scanner
// profile (Issue #3982). Never built or served: it lives under a
// dot-directory outside web/. Each construct plants one finding the eslint
// profile (image-owned config) and the semgrep profile (upstream React rules +
// CFGMS rules) must recover; `lanes/scan_fixtures_test.py` asserts they do.

export function Planted(props: { html: string }) {
  const el = document.getElementById('planted')
  if (el) {
    // no-restricted-properties (innerHTML) / cfgms-html-injection-sink
    el.innerHTML = props.html
  }
  // react/no-danger, no-restricted-syntax / react-dangerouslysetinnerhtml,
  // cfgms-react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: props.html }} />
}
