// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Image-owned ESLint configuration for the security-review finder lanes
// (Issue #3982, epic #3975). Installed to /opt/cfgms-scanner/eslint.config.js
// and loaded ONLY via `--no-config-lookup --config <this file>` by
// `.claude/scripts/security-review/lanes/scan_profiles.py`.
//
// Why a second config and not web/eslint.config.js: a flat config is
// executable JavaScript. The lane container scans an UNTRUSTED snapshot of
// the repository next to a live subscription credential, so nothing under
// /workspace may ever be loaded as code -- not the audited project's
// eslint.config.js, not its node_modules, not its package.json scripts.
// This file and the packages beside it are the only parser, plugins and
// rules the scan ever executes. The security rules below are the same ones
// web/eslint.config.js enforces in CI; keep the two in step by hand.
import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import security from 'eslint-plugin-security'

// eslint-plugin-security ships its recommended set at "warn"; run it at
// "error" so its findings are unambiguous in the JSON the model reads.
const securityRulesAtError = Object.fromEntries(
  Object.keys(security.configs.recommended.rules).map((rule) => [rule, 'error']),
)

// HTML-injection sinks. React escapes rendered values by default; every
// construct below bypasses that protection.
const htmlSinkBans = {
  'react/no-danger': 'error',
  'react/no-danger-with-children': 'error',
  'no-restricted-properties': [
    'error',
    { property: 'innerHTML', message: 'HTML-injection sink. Render through React instead.' },
    { property: 'outerHTML', message: 'HTML-injection sink. Render through React instead.' },
    { property: 'insertAdjacentHTML', message: 'HTML-injection sink. Render through React instead.' },
    { property: 'dangerouslySetInnerHTML', message: 'Banned HTML-injection sink. Render through React instead.' },
    { object: 'document', property: 'write', message: 'HTML-injection sink. Render through React instead.' },
    { object: 'document', property: 'writeln', message: 'HTML-injection sink. Render through React instead.' },
  ],
  'no-restricted-syntax': [
    'error',
    {
      selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
      message: 'dangerouslySetInnerHTML is banned (HTML-injection sink).',
    },
  ],
  // Runtime code composition is banned repo-wide (CLAUDE.md banned patterns).
  'no-eval': 'error',
  'no-implied-eval': 'error',
  'no-new-func': 'error',
}

export default tseslint.config(
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    plugins: {
      react,
      'react-hooks': reactHooks,
      security,
    },
    languageOptions: {
      globals: { ...globals.browser },
    },
    settings: {
      // Never `detect`: detection reads the audited project's package.json.
      react: { version: '19.0' },
    },
    rules: {
      ...react.configs.flat.recommended.rules,
      ...react.configs.flat['jsx-runtime'].rules,
      ...reactHooks.configs['recommended-latest'].rules,
      ...securityRulesAtError,
      ...htmlSinkBans,
    },
  },
)
