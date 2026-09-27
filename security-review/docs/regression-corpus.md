# Regression corpus index

Defects this repository has had, each pinned to a commit where the defect is still present. A
sweep run against that commit either surfaces it or does not, which is a number.

The corpus answers two questions a sweep cannot answer about itself: does a given model find real
defects, and does a change to the harness make it find fewer.

## Entry rules

- `id` is permanent. Retire, never reuse.
- `commit` must be a commit where the defect is PRESENT, normally the parent of its fix.
- **An entry must be a defect, verified in the fix commit's own body.** A subject line is not
  evidence: a redesign, a refactor, or a salvage of files a previous commit missed all read like
  fixes and are not defects. An entry that was never a defect makes every score meaningless in
  the worst direction, marking a model down for not finding something that was never there.
- Seed an entry by hand only where a scenario has no historical instance, and mark it seeded so a
  score can be read with and without.

## Scoring rule

An entry is **found** when a sweep against its `commit` reports a finding whose `file` is one of
the entry's files and whose `vuln_class` matches. Since Issue #4134 a consolidated finding's
`vuln_class` **is the normalised `cwe`**, not the free-text label a lane wrote, so an entry's
`vuln_class` column should hold a CWE identifier. Line numbers are never compared -- they rot. A
finding on the right file with the wrong class is **near**, counted separately: the reviewer looked
in the right place and named the wrong thing.

A score is comparable only against another score over the same corpus revision **and the same
matching rule**. Record both beside any number.

**Scores taken before Issue #4134 are not comparable with scores taken after it**, even over an
identical corpus revision. That change made the matching class the normalised `cwe` rather than the
lane's prose, so entries that could previously score `near` at best can now score `found` — the
number moved because the rule moved, not because a model improved. Re-run any baseline you intend
to compare against rather than trusting a recorded figure.

## The corpus is not the only signal

A model that finds every entry has found defects someone already fixed. That is a regression check,
not a measure of what a sweep is for.

Closure rate -- the share of hypotheses a lane resolves as `investigated` or `candidate_found`
rather than `inconclusive` -- pulls the other way: it rewards narrow, easily-closed hypotheses and
punishes the broad cross-boundary guess most likely to find something deep. Read the two together,
never either alone, and never tune a prompt against one of them.

## Entries

Detail lives outside this repository, under `$CFGMS_SECURITY_REVIEW_BASE/corpus/<id>.json`
(default `~/.cache/cfgms-security-review/corpus/`), because an entry describes a defect that is
still present at the commit it names. This index carries only what is safe to publish.

| id | commit | fixed by | scenario | class | defect |
|---|---|---|---|---|---|
| RC-01 | `2917eafe` | `3d03e725` | TS-12 | CWE-269 | operator payload dispatch had no server-side bound on how many targets one signed payload could reach |
| RC-02 | `70a1c805` | `46e8ee71` | TS-15 | CWE-345 | a composition path yielding a nil audit store passed storage validation, so a controller could run with no audit trail and fail only at first write |
| RC-03 | `66e8b76c` | `87d1630f` | TS-07 | CWE-639 | the steward config-push endpoint took the target tenant from the steward record with no check against the caller's tenant subtree |
| RC-04 | `135f603b` | `4ed70b39` | TS-09 | CWE-295 | steward-side operator signature verification accepted any client-auth certificate chaining to the controller CA, without the administrator marker check |
| RC-05 | `7a25a97c` | `4eed415a` | TS-07 | CWE-636 | the exec tenant-scope check allowed dispatch when the fleet lookup it depended on failed or was absent |
| RC-06 | `d76aacb8` | `3a7bf619` | TS-07 | CWE-639 | the session-revoke endpoint acted on any session ID without checking the session belonged to the caller's tenant |
| RC-07 | `27dd904b` | `a2bcbe44` | TS-07 | CWE-863 | cross-tenant guards keyed on a principal scope flag that the web-session path always set to global, so they never fired for session callers |
| RC-08 | `f5f0d00e` | `3f713b29` | TS-07 | CWE-639 | role read, update, delete and create handlers had no tenant-subtree check, and create trusted a tenant ID from the request |
| RC-09 | `97da435f` | `2a0ed673` | TS-07 | CWE-639 | report and compliance reads took their tenant scope from caller-supplied parameters instead of the authenticated principal |
| RC-10 | `91bca2c1` | `0ec397c9` | TS-10 | CWE-347 | the steward-binary signature covered only the content hash, not version or platform, so an older signed build could pass the downgrade guard |
| RC-11 | `67559830` | `d2de5e44` | TS-05 | CWE-639 | the config-sync handler served configuration for the steward ID named in the request without binding it to the mTLS peer identity |
| RC-12 | `8116cfe2` | `d1dde2c5` | TS-04 | CWE-639 | the control-plane register call took steward identity from the request body instead of the authenticated peer certificate |
| RC-13 | `f3ffd05e` | `b69daef8` | TS-03 | CWE-78 | a resource object identifier was interpolated unvalidated into generated script text |
| RC-14 | `a91af2b1` | `1c2291ba` | TS-04 | CWE-367 | single-use registration tokens used a non-atomic check-then-save whose failure was ignored, allowing concurrent reuse |
| RC-15 | `3390e44e` | `ea33242e` | TS-01 | CWE-208 | the webhook bearer token was compared with non-constant-time equality |
| RC-16 | `25597fea` | `c2fe4f75` | TS-03 | CWE-22 | a caller-controlled config key field became the leaf filename through a plain path join, outside the traversal-safe join |
| RC-17 | `0d90acec` | `ff44980e` | TS-03 | CWE-74 | operator-supplied values were interpolated unescaped into generated guest boot configuration |

Small and verified beats large and wrong: a score over entries that were real defects is
meaningful, and a score padded with entries that never were is not. RC-03 to RC-17 came from a read
of 49 fix commits: each fix commit's body states the defect, and the defective construct is present
at the pinned parent. Entries are added as real sweeps confirm findings, and as fix commits are read
rather than skimmed.

Several entries share a family (missing tenant or identity binding) where neighbouring CWE classes
are defensible. Each entry's detail file records `alt_classes`; a finding naming one of those scores
`near` under the matching rule above, and should be read as a class disagreement, not a miss.

## Negative set

Known-clean code, for measuring the verification stage in the other direction. A corpus entry is a
known-real defect, so a `not_reachable` or `guarded` verdict on one is a false negative. These rows
are code that is correctly guarded, so a `reachable_*` verdict on one is a false positive. Without
this set, a verifier that called everything reachable would look perfect.

Each row is the fixed form of a corpus defect, or a close sibling, pinned at a commit where the guard
is present. `class` is the defect a finder might wrongly claim there. Same id rule as the entries:
permanent, never reused.

| id | commit | file | symbol | class | why it is safe |
|---|---|---|---|---|---|
| NC-01 | `15a7d27b` | `features/controller/api/handlers_stewards.go` | `handleUpdateStewardConfig` | CWE-639 | caller-subtree check before the body is read; the permission requires strong assurance |
| NC-02 | `15a7d27b` | `features/controller/api/handlers_sessions.go` | `handleSessionRevoke` | CWE-639 | a scoped caller may revoke only a session in its own tenant; others get the not-found response |
| NC-03 | `15a7d27b` | `features/steward/commands/execute_script.go` | `verifyOperatorCert` | CWE-295 | checks the chain, the client-auth usage, the payload-signing marker and revocation |
| NC-04 | `15a7d27b` | `features/controller/transport/config_handler.go` | `ConfigHandler.HandleGRPC` | CWE-639 | the requested steward ID must equal the mTLS peer identity |
| NC-05 | `15a7d27b` | `features/workflow/trigger/webhook.go` | `validateBearerToken` | CWE-208 | refuses an unconfigured token and compares in constant time |
| NC-06 | `15a7d27b` | `pkg/storage/providers/flatfile/config_store.go` | `configPath` | CWE-22 | key fields are validated as leaf names and the whole path is built by the safe join |
| NC-07 | `15a7d27b` | `features/modules/extended/activedirectory/module.go` | `queryADObjectSystem` | CWE-78 | the object identifier passes an allowlist check before any script is built |
| NC-08 | `15a7d27b` | `features/controller/api/handlers_tenants.go` | `handleGetTenant` | CWE-639 | ancestry-based tenant access check; denial returns the same response as not-found |
| NC-09 | `15a7d27b` | `features/controller/api/handlers_certificates.go` | `handleListCertificates` | CWE-639 | scoped callers get subtree-filtered results, and a missing store fails closed |

The verification score (`corpus.score_verdicts`) counts both directions from these two tables, with
`undetermined` and missing verdicts counted on their own and never as errors. Verdict stability across
repeated runs of the same item (`corpus.verdict_stability`) is a separate number: a verifier can be
reliably wrong or erratically right, and one figure cannot say which.

## Candidates rejected on inspection

Kept so they are not re-proposed. Each looked like a fix and was not:

- Registration moving the keypair generation to the steward. A deliberate redesign (ADR-032), not a
  defect in the flow it replaced.
- Cluster-visible revocation list. Architecture work, and the commit is partly a salvage of files an
  earlier commit left untracked.
- Failed-closed defects (unscoped reads that returned nothing, errors that became deny, an admin that
  saw too little). They are real bugs, but availability bugs; no caller gained access.
- Hardening with no defect path: a new justification requirement, a JWT tenant re-check against a
  mis-stored token, and refactors of a "latent-bug shape" with identical results at every site.
- Squashed work-in-progress commits whose body describes only build or test fixes. The body rule
  cannot be met, whatever the subject says.
- Defects introduced and fixed inside the same pull request (for example a compare-and-swap
  primitive's own key collision), since they never shipped.
