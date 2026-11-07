#!/usr/bin/env python3
"""
secrets_scan: candidate and agent-text secret scanning (DESIGN.md §6.4).

Three detectors, run before VALIDATE and again before PUBLISH:

  1. exact values of every credential mounted into the agent container, in
     raw, base64 (standard and URL-safe, all three byte alignments) and hex
     (lower and upper) form;
  2. a credential-name denylist (basename globs, taken from the removed
     headless entrypoint's WIP salvage), on changed paths;
  3. an external generic scanner hook: `trufflehog` run from the cfg-agent
     image with no network and the scan dir mounted read-only (default), a
     host binary only when CFGMS_FSM_TRUFFLEHOG names one, or disabled with
     CFGMS_FSM_TRUFFLEHOG=off (recorded as a warning).

Findings never carry the secret value: only a location and the credential
*name*.
"""

import base64
import binascii
import fnmatch
import json
import os
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path

#: Credential basename globs (from the removed headless entrypoint's salvage).
CREDENTIAL_NAME_GLOBS = (
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", ".netrc", ".npmrc", ".pypirc",
    ".git-credentials", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx",
)

#: Values shorter than this are not scanned for: they would match by accident.
MIN_SECRET_LEN = 8


@dataclass
class Finding:
    detector: str      # "credential_value" | "credential_name" | "external"
    source: str        # "diff:<path>" | "text:<name>" | "path:<path>"
    line: int          # 1-based, 0 when not line-addressable
    credential: str    # credential name (never its value) or detector name

    def to_dict(self):
        return asdict(self)

    def describe(self):
        loc = f"{self.source}:{self.line}" if self.line else self.source
        return f"{self.detector} ({self.credential}) at {loc} [value redacted]"


def credential_name_hit(path):
    base = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(base, g) for g in CREDENTIAL_NAME_GLOBS)


def value_variants(value):
    """Encodings of `value` that a leak could take. Returns a set of strings."""
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    out = set()
    if len(raw) < MIN_SECRET_LEN:
        return out
    out.add(raw.decode("utf-8", "replace"))
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        for shift in range(3):
            # base64 of the value embedded at any byte offset contains this core.
            prefix = b"\0" * shift
            s = enc(prefix + raw).decode("ascii")
            # Keep only output chars whose 6 bits come entirely from `raw`:
            # char i covers bits [6i, 6i+6); the prefix fills bits [0, 8*shift).
            lead = (8 * shift + 5) // 6
            end = (8 * (shift + len(raw))) // 6
            core = s[lead:end]
            if len(core) >= MIN_SECRET_LEN:
                out.add(core)
        full = enc(raw).decode("ascii")
        out.add(full)
        out.add(full.rstrip("="))
    hx = binascii.hexlify(raw).decode("ascii")
    out.add(hx)
    out.add(hx.upper())
    return {v for v in out if len(v) >= MIN_SECRET_LEN}


class Scanner:
    """Holds the credential values for one run; scans texts and candidate diffs."""

    def __init__(self, credentials, external=None, warnings=None):
        # credentials: {name: value}
        self._variants = []
        self.warnings = warnings if warnings is not None else []
        for name, value in (credentials or {}).items():
            if not value:
                continue
            vs = value_variants(value)
            if not vs:
                self.warnings.append(f"credential {name} shorter than {MIN_SECRET_LEN} chars: not scanned")
                continue
            self._variants.append((name, sorted(vs, key=len, reverse=True)))
        self.external = external

    def scan_text(self, source, text):
        findings = []
        if text is None:
            return findings
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
        for lineno, line in enumerate(text.splitlines() or [text], 1):
            for name, variants in self._variants:
                if any(v in line for v in variants):
                    findings.append(Finding("credential_value", source, lineno, name))
        # also catch a value split across a line break (wrapped base64)
        if not findings and "\n" in text:
            flat = text.replace("\r", "").replace("\n", "")
            for name, variants in self._variants:
                if any(v in flat for v in variants):
                    findings.append(Finding("credential_value", source, 0, name))
        return findings

    def _new_root(self, scan_dir):
        if scan_dir is None:
            return None
        scan_dir = Path(scan_dir)
        scan_dir.mkdir(parents=True, exist_ok=True)
        n = 0
        while (scan_dir / f"s{n}").exists():
            n += 1
        root = scan_dir / f"s{n}"
        root.mkdir()
        return root

    def scan_candidate(self, repo, base, tree, changed, scan_dir=None):
        """Scan changed blobs of `tree` vs `base`, one blob at a time.

        `changed` is a list of snapshot.Entry. Each blob is read, scanned and
        (when an external scanner is configured) written to a fresh directory
        under `scan_dir` before the next one is read, so memory stays bounded
        by the largest single blob (the per-file cap). The external scanner
        then runs once over that directory.
        """
        findings = []
        root = self._new_root(scan_dir) if self.external else None
        for e in changed:
            if e.status == "D":
                continue
            if credential_name_hit(e.path):
                findings.append(Finding("credential_name", f"path:{e.path}", 0, "denylist"))
            findings.extend(self.scan_text(f"path:{e.path}", e.path))
            if e.new_mode in ("100644", "100755", "120000"):
                data = repo.blob(e.new_sha)
                findings.extend(self.scan_text(f"diff:{e.path}", data))
                if root is not None:
                    _write_scan_file(root, e.path, data)
                del data
        if root is not None:
            findings.extend(self.external(root, self.warnings))
        return findings

    def scan_texts(self, texts, scan_dir=None):
        """texts: {name: str}. Returns findings over agent-written text."""
        findings = []
        for name, text in texts.items():
            findings.extend(self.scan_text(f"text:{name}", text))
        root = self._new_root(scan_dir) if (self.external and texts) else None
        if root is not None:
            for n, t in texts.items():
                _write_scan_file(root, f"text/{n}.txt", (t or "").encode("utf-8"))
            findings.extend(self.external(root, self.warnings))
        return findings


def _write_scan_file(root, rel, data):
    dest = Path(root) / _safe_rel(rel)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "xb") as fh:          # fresh supervisor-owned dir: no links
        fh.write(data)


def _safe_rel(path):
    parts = [p for p in path.split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "_"


def _parse_trufflehog(stdout, prefix):
    found = []
    for line in stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "DetectorName" not in rec:
            continue
        src = (((rec.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        fpath = str(src.get("file", ""))
        if fpath.startswith(prefix):
            fpath = fpath[len(prefix):].lstrip("/")
        else:
            fpath = Path(fpath).name
        found.append(Finding("external", f"diff:{fpath}", int(src.get("line") or 0),
                             str(rec.get("DetectorName"))[:60]))
    return found


def _finish(proc, found, warnings):
    if proc.returncode not in (0, 183) and not found:
        warnings.append(f"external scanner exited {proc.returncode}")
        return [Finding("external", "scanner", 0, "scanner_error")]
    return found


TRUFFLEHOG_ARGS = ("--json", "--no-update", "--no-verification")


def image_scanner_hook(image=None, docker="docker", timeout=600):
    """trufflehog from the cfg-agent image: `docker run --rm --network none`,
    scan dir mounted read-only, no credential, no other mount."""
    image = image or os.environ.get("CFGMS_FSM_IMAGE", "cfg-agent:latest")

    def run(root, warnings):
        argv = [docker, "run", "--rm", "--network", "none", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", "512",
                "--label", "cfg-agent-scan=true",
                "-v", f"{root}:/scan:ro", "--entrypoint", "trufflehog", image,
                "filesystem", "/scan", *TRUFFLEHOG_ARGS]
        env = {k: v for k, v in os.environ.items()
               if k not in ("GH_TOKEN", "GITHUB_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                            "CFGMS_FSM_PUSH_TOKEN")}
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            warnings.append(f"external scanner failed to run: {type(exc).__name__}")
            return [Finding("external", "scanner", 0, "scanner_error")]
        return _finish(proc, _parse_trufflehog(proc.stdout, "/scan"), warnings)

    return run


def host_scanner_hook(binary, timeout=300):
    """trufflehog binary on the host; used only when CFGMS_FSM_TRUFFLEHOG names it."""

    def run(root, warnings):
        try:
            proc = subprocess.run([binary, "filesystem", str(root), *TRUFFLEHOG_ARGS],
                                  capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            warnings.append(f"external scanner failed to run: {type(exc).__name__}")
            return [Finding("external", "scanner", 0, "scanner_error")]
        return _finish(proc, _parse_trufflehog(proc.stdout, str(root)), warnings)

    return run


def scanner_hook(choice=None):
    """External scanner selected by CFGMS_FSM_TRUFFLEHOG: unset or `image`
    (default) runs it in the cfg-agent image; `off` disables it; any other
    value is the path of a host trufflehog binary."""
    choice = choice if choice is not None else os.environ.get("CFGMS_FSM_TRUFFLEHOG", "image")
    if choice == "off":
        return None
    if choice in ("", "image"):
        return image_scanner_hook()
    return host_scanner_hook(choice)
