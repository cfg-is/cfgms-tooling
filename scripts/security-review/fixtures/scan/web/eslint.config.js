// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// DECOY. A snapshot-supplied ESLint config that must NEVER be loaded by the
// security-review scanner (Issue #3982): the lane scans an untrusted checkout
// next to a live credential, and a flat config is executable JavaScript. The
// eslint profile runs with `--no-config-lookup --config <image path>`, so this
// file is inert data. `lanes/scan_fixtures_test.py` asserts the marker string
// below never appears in scanner output; if it does, the snapshot's code ran.
throw new Error('SNAPSHOT_ESLINT_CONFIG_WAS_LOADED')
