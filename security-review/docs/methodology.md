# Security review methodology

This document is the review methodology every finder lane of the security review
harness is held to. It states what CFGMS considers a security defect, who the attacker
is assumed to be, and what `critical`, `high`, `medium` and `low` mean here. A human
owns it. It is not generated, and it must not be edited by an autonomous agent: a
miscalibrated rubric degrades every future sweep in the same direction, every lane
agrees with every other lane because they were all told the same wrong thing, and no
test can detect that.

Two audiences read it:

- **Operators** triaging a consolidated report, who need to know what a severity in the
  report means and which attacker it assumes.
- **Finder lanes**, which receive parts of this document inside every step prompt
  through `harness_runner.py`. The lanes never read this file directly; the harness
  runner does, once, at import, and hands the same text to every lane.

## How this document reaches a finder lane

The document is split into two kinds of content, marked with HTML comments that
`.claude/skills/security-review/lanes/harness_runner.py` parses:

- **The compact core**, between the `methodology-core:begin` and `methodology-core:end`
  HTML comments. It is inlined into every step prompt of every lane,
  between the shared system prompt and the shared output-schema description. It has a
  character ceiling, `METHODOLOGY_CORE_MAX_CHARS`, enforced when the document is
  loaded and asserted by `harness_runner_test.py`. The ceiling exists because the core
  is paid once per step per lane, at roughly 250 steps per lane.
- **Worked examples (severity anchors)**, each between an `anchor:begin` and an
  `anchor:end` HTML comment, the opening one carrying an `id`, a `severity` and a comma-separated `tags`
  list. For every step, `harness_runner.select_anchors()` picks exactly one anchor per
  severity level: the anchor whose tags overlap most with the step's own scope, files,
  description and hypotheses, ties broken by document order. The selection is a pure
  function of the step's content and this document, so the same step always receives
  the same anchors. Each anchor has its own ceiling, `ANCHOR_MAX_CHARS`.

Everything outside those markers, including this section, is for human readers only and
never reaches a prompt.

There is one copy of this text, here. `harness_runner.py` holds the only loading code
and the only constants (`METHODOLOGY_CORE`, `METHODOLOGY_ANCHORS`), and every lane's
`build_prompt` calls `harness_runner.shared_preamble(step)` rather than assembling its
own. A test fails if a second definition appears anywhere under
`.claude/skills/security-review/`. The choices behind this shape, and the alternatives
that were rejected, are recorded in
[`.claude/skills/security-review/docs/harness-architecture.md`](harness-architecture.md)
under *Review methodology: compact core and per-step anchors*.

### Editing rules

- Keep the marker comments exactly as they are. The loader fails closed on a missing or
  duplicated marker, and the lanes then do not start.
- Never write a full marker comment anywhere else in this file, not even in prose or in
  backticks. The loader counts exact occurrences, and a second one is a duplicate.
- Keep the core under its ceiling and every anchor under its ceiling. The loader
  rejects an oversized core or anchor; the tests say which.
- Keep at least two anchors per severity level. The loader rejects a level with fewer.
- Give a new anchor a unique `id` and tags that name the subsystem it is about, in the
  words a plan step's scope, file paths and hypotheses would use (`cert`, `tenant`,
  `module`, `registration`, `log`). Tags are matched as whole lower-case tokens after
  splitting paths and camel-case identifiers.
- Any change to the core or to an anchor changes `prompt_version` on every envelope
  written afterwards, so a sweep spanning the change is visible as such.

<!-- methodology-core:begin -->
## Threat model

CFGMS is a zero-trust, multi-tenant configuration management system. A **controller**
(central, SaaS or on-premises) manages **stewards** (agents on Windows, Linux and macOS
endpoints) over mutual-TLS gRPC-over-QUIC. Administrators reach the controller through a
REST API and the `cfg` CLI using an mTLS bundle. Tenants form a tree
(`root/msp-a/client-1`); configuration inherits root to leaf. Storage defaults to the
`flatfile` provider (`sqlite` and `database` are alternatives); secrets live in the OS keychain or SOPS, never in cleartext on
disk. Modules are publisher-signed out-of-process binaries; the controller verifies and
forwards signatures intact and never re-signs.

Standing assumptions. Judge every finding against them:

1. **Any steward host may already be compromised.** Root on one endpoint is the
   attacker's starting position, not a prize. The boundary that matters is between that
   steward and everything else: the controller, other stewards, other tenants.
2. **Admin accounts may be phished or taken over for short periods.** Rarely-touched
   settings (`module_trust.mode: strict`, additional trusted publishers, publisher
   revocations) exist to bound what a compromised admin or a compromised controller can
   do to endpoints. A defect that lets an attacker weaken or bypass one of those bounds
   is judged by the blast radius the bound was meant to contain.
3. **Endpoints run application allowlisting and EDR.** Code CFGMS runs on an endpoint
   must behave like predictable admin tooling: declared paths, signed binaries, no
   runtime code composition (`iex`, `bash -c "<string>"`, `eval`, `-EncodedCommand`).
4. **A tenant must never read or affect a sibling or ancestor tenant.** Tenant identity
   comes from the authenticated principal, never from a client-supplied path.

Trust boundaries, in decreasing attacker distance: internet to REST/gRPC listener;
enrolled steward to controller; tenant admin to another tenant; module publisher to the
hosts that run the module; controller to steward (bounded by trust modes and end-to-end
signatures).

## Vulnerability classes in scope

Set `cwe` to one identifier from this list, or to `other: <short label>` when none
fits. The escape is allowed and expected. Never force a finding into the nearest
identifier, and never drop one because no identifier fits. Set `vuln_class` to the
Class column below: prose, never a bare identifier.

| Identifier | Class | Typical CFGMS surface |
|---|---|---|
| CWE-295 | Improper certificate validation | mTLS chain, hostname, expiry or revocation checks skipped |
| CWE-287 | Improper authentication | gRPC/REST boundary, registration tokens |
| CWE-306 | Missing authentication for critical function | unauthenticated admin or fleet operation |
| CWE-862 | Missing authorization | handler with no permission check |
| CWE-863 | Incorrect authorization | tenant scoping, prefix or path confusion, wrong principal |
| CWE-269 | Improper privilege management | implicit admin, escalation through inheritance |
| CWE-347 | Improper signature verification | module bundles, signed admin commands, payload markers |
| CWE-345 | Insufficient data authenticity | unsigned or stale configuration accepted |
| CWE-613 | Insufficient session or credential expiration | tokens, leases, certificates accepted past their window |
| CWE-330 | Insufficiently random values | tokens, identifiers, nonces |
| CWE-208 | Observable timing discrepancy | non-constant-time comparison of tokens or signatures |
| CWE-798 | Hard-coded credentials | any credential in source or fixtures |
| CWE-312 | Cleartext storage of sensitive information | secrets on disk, in caches, in temp files |
| CWE-532 | Sensitive information in log | secrets or tokens logged |
| CWE-117 | Log output neutralization | unsanitized steward or admin input in logs |
| CWE-209 | Sensitive information in error message | internal paths, identities, other tenants' data |
| CWE-78 | OS command injection | command construction, banned shell patterns |
| CWE-88 | Argument injection | attacker-controlled argv or flags |
| CWE-89 | SQL injection | any non-parameterized query |
| CWE-22 | Path traversal | tenant paths, module cache, file staging |
| CWE-59 | Link following | symlinks in staging, cache or convergence paths |
| CWE-502 | Deserialization of untrusted data | YAML, JSON, protobuf handled unsafely |
| CWE-20 | Improper input validation at a trust boundary | anything crossing a boundary above, unchecked |
| CWE-362 | Race condition, check-then-act | staging, atomic writes, convergence, leadership |
| CWE-400 | Uncontrolled resource consumption | only when a lower-trust party can trigger it |

## Severity rubric

Severity is **impact given the assumed attacker**. Confidence is a separate field; a
low-confidence critical is still critical. Name the attacker tier in `evidence`.

Attacker tiers:

- **T0 Network party.** Reaches a controller listener; holds no credential.
- **T1 Compromised steward.** Root on one enrolled endpoint; holds that steward's mTLS
  identity and registration material.
- **T2 Compromised tenant admin.** Holds a valid admin bundle or session for one tenant
  subtree, for a short window.
- **T3 Compromised controller or root admin.** The worst case the design bounds rather
  than prevents. A finding that needs T3 is `low`, unless the defect is in a control
  whose purpose is to bound T3; then judge it by the blast radius that control was meant
  to contain.
- **P Untrusted publisher.** Produces a module bundle whose publisher is not in the trust
  store.

Levels:

- **critical.** An attacker below T3 gains control of the controller, of stewards other
  than their own, or of another tenant's configuration: an unauthenticated or
  steward-credential path to admin capability; code execution on other endpoints; a
  cross-tenant write, from any tier including T2; an mTLS or signature verification
  bypass on the control path; unknown-publisher code running on an endpoint. Also a
  T3-bounding control that fails, judged by the blast radius it was meant to contain.
- **high.** A cross-tenant read, from any tier; T2 bypassing or weakening a blast-radius
  bound inside its own tenant so that its reach grows to what the bound was meant to
  deny (adding a trusted publisher, moving stewards out of `strict`); T1 reading other
  stewards' secrets or configuration in its own tenant, or keeping access past
  revocation or expiry; T0 reading sensitive fleet data, or cheaply taking the
  controller down.
- **medium.** Impact stays inside the attacker's own tenant or own host, and the bounds
  still hold, but a stated control is violated: a privileged action without audit; a
  rarely-touched setting changeable without its designed friction while the change stays
  authorized, recorded and reversible; false state reported to the controller; a
  cleartext secret on the attacker's own disk; log injection from a T1 input; local user
  to root on one endpoint through a CFGMS-owned path.
- **low.** A defence-in-depth gap with no boundary crossing shown: validation missing
  where every caller is already T3; weak randomness behind another control;
  non-sensitive internals exposed; hardening misses. Report it anyway.

Moving a level. The level definitions take precedence; there is no arithmetic. Reassess
against them, and say so in `evidence`, when the required tier changes (T2 to T1, T1 to
T0), the scope changes (own host, own tenant, cross-tenant, fleet), a second independent
control blocks the path today (name it; usually one level down), or the path needs an
insecure non-default prerequisite such as a disabled verification setting (usually one
level down). A development-only prerequisite (`module_trust.mode: bypass`) makes it
`low`: the operator disabled the control. A protective setting such as `strict` never
lowers severity; a defect in the control it enables is judged by the blast radius that
control bounds.
<!-- methodology-core:end -->

## Worked examples (severity anchors)

Each example below is an **illustrative, CFGMS-shaped defect**, written to calibrate the
scale. None of them describes a known defect in the codebase. Each states what makes it
that level, which attacker tier it assumes, and what would move it one level up or
down. A lane receives one example per level, chosen by subject-matter overlap with its
step.

### Critical

<!-- anchor:begin id=crit-mtls-verify severity=critical tags=tls,mtls,cert,certificate,certs,ca,chain,quic,transport,handshake,verify,dial,client,server -->
**Steward-to-controller TLS accepts any server certificate.** The QUIC client
configuration for the steward's control-plane connection installs a verification
callback that returns success without checking the presented chain against the
controller CA. Attacker: T0, on the network path. Level: critical, because a network
party with no credential impersonates the controller and pushes configuration or module
bundles to every steward that connects through it, with no user interaction. Down to
high if the unchecked connection only carries telemetry outbound and accepts no
commands or configuration: a network party then reads fleet inventory data, a T0 read
of sensitive fleet data, but pushes nothing. It cannot move up; record the fleet-wide
scope in `evidence`.
<!-- anchor:end -->

<!-- anchor:begin id=crit-strict-mode-bypass severity=critical tags=module,modules,bundle,bundles,publisher,publishers,signature,signing,trust,trusted,strict,staging,cache,manifest,verify,approval -->
**Publisher trust check reads the trusted-publisher list from the bundle itself.** The
signature verifier takes the set of trusted publishers from the metadata of the bundle
it is verifying, instead of from the publisher identity baked into the steward binary
plus the operator's additional-publishers setting. Attacker: P alone if the defect is in
the controller's verifier, since any publisher's bundle then passes and reaches every
endpoint in `controller` mode; T3 together with P if it is in the steward's `strict`
check, since strict mode exists exactly to bound a compromised controller. Level:
critical either way: unknown-publisher code runs on endpoints, and in the strict case
the T3-bounding control has failed. Down to high if staging still requires an explicit
admin approval of the bundle, so P also needs T2 (a phished admin approving it). Down to
low if it is reachable only under `bypass`: the operator disabled the control.
<!-- anchor:end -->

<!-- anchor:begin id=crit-tenant-from-path severity=critical tags=tenant,tenants,path,subtree,inheritance,scope,principal,rest,api,handler,http,authorization,authz,admin,write,config -->
**A configuration write handler takes the tenant from the URL, not the principal.** A
REST handler resolves the target tenant from a client-supplied path segment and never
checks that it sits under the authenticated admin's own tenant subtree. Attacker: T2.
Level: critical: this is a cross-tenant write, so a phished admin of one client alters
configuration that deploys to another client's fleet. Down to high if the handler is
read-only, making it a cross-tenant read. Down to high if a downstream store check
refuses the write today, since one remaining control stands between T2 and another
tenant's fleet; report it and name that check.
<!-- anchor:end -->

### High

<!-- anchor:begin id=high-regtoken-replay severity=high tags=registration,regtoken,token,tokens,enrol,enroll,enrolment,enrollment,expiry,expires,reuse,replay,generator,store,device,identity -->
**A registration token is honoured after expiry or reuse.** The registration store
checks the token's signature but not its expiry or its single-use marker, so a captured
token enrols additional devices indefinitely. Attacker: T1, since a compromised steward
holds its own enrolment material. Level: high: the attacker mints additional certified
identities inside the tenant and gains a tenant-wide presence its one host never had. Up
to critical if the token is root-scoped or the new identity lands in a different tenant.
Down to medium if enrolment still requires an admin approval step before a certificate
is issued.
<!-- anchor:end -->

<!-- anchor:begin id=high-secrets-device-filter severity=high tags=secret,secrets,sops,keychain,dataplane,distribution,device,devices,steward,fetch,pull,credential,credentials -->
**A data-plane secret fetch filters by tenant but not by device.** The steward-facing
secret distribution endpoint returns every secret in the caller's tenant rather than only
the secrets targeted at the calling device. Attacker: T1. Level: high: a compromised
steward reads secrets meant for sibling stewards, so one host's compromise becomes
tenant-wide credential exposure. Up to critical if the exposed set includes a credential
that grants control of the controller or of other stewards, such as a registration token
or an admin bundle; a cross-tenant read of ordinary secrets stays high. Down to medium
if the values are non-privileged configuration rather than credentials.
<!-- anchor:end -->

<!-- anchor:begin id=high-signer-revocation severity=high tags=signing,signer,signature,revocation,revoke,revoked,rotation,rotate,command,commands,payload,marker,cursor,lifecycle,cert,certificate,mtls -->
**A signed admin command is accepted after the signer was revoked.** Command
verification checks the signature against the signing certificate embedded in the
command and never consults the revocation store or the current signing cursor.
Attacker: T2 whose access was revoked once a takeover was noticed. Level: high: the
attacker keeps issuing valid-looking commands to the tenant's stewards past the point
the operator believed access was cut off, defeating the recovery path the threat model
relies on. Up to critical if an accepted command can alter trust settings or run code
fleet-wide. Down to medium if the window is already bounded by a short certificate
lifetime enforced elsewhere.
<!-- anchor:end -->

### Medium

<!-- anchor:begin id=med-log-injection severity=medium tags=log,logs,logging,logger,sanitize,sanitizelogvalue,slog,hostname,inventory,telemetry,injection,audit -->
**A steward-reported hostname is written to controller logs unsanitized.** An inventory
handler logs the device's self-reported hostname raw, so newline and control characters
forge log entries. Attacker: T1. Level: medium: the attacker corrupts operator-facing
logs on the controller but crosses no confidentiality or integrity boundary for
configuration or secrets. Up to high if the log is the audit trail used for
authorization decisions or incident evidence, or if the injected text reaches another
tenant's view. Down to low if the value was validated to a strict character set before
it reached the logger.
<!-- anchor:end -->

<!-- anchor:begin id=med-cleartext-temp severity=medium tags=cleartext,plaintext,disk,temp,tmp,file,files,permissions,perm,mode,secret,credential,module,render,write -->
**A module renders a credential to a temp file with default permissions.** A steward
module writes a fetched credential to disk in cleartext before handing it to the managed
application, and leaves it readable by other local users. Attacker: a local user on that
same endpoint, below T1. Level: medium: the threat model already grants root on the host
to T1, so exposure on the attacker's own disk is not a boundary crossing, but "no
cleartext secrets on disk" is a stated control, and other local users gain a credential
they did not have. Up to high if the credential is tenant-wide, or the file survives
across runs on a shared host. Down to low if the material is the steward's own
certificate, already available to root.
<!-- anchor:end -->

<!-- anchor:begin id=med-convergence-symlink severity=medium tags=file,symlink,link,toctou,race,check,nofollow,convergence,converge,staging,atomic,rename,module,path,drift -->
**The file module follows a symlink when converging a managed path.** The file module
checks a path's state, then writes through it without a no-follow flag, so a local user
who controls a parent directory redirects the write. Attacker: a local non-root user on
one endpoint. Level: medium: local escalation to root on a single host through a
CFGMS-owned path, bounded to that host and needing a local foothold. Up to high if the
managed path is user-writable by default, so no foothold beyond an ordinary account is
needed. Up to critical if T1 on one host can trigger the redirected root write on
another host, since that is control of another steward. Down to low if the path is
under a steward-owned, root-only directory.
<!-- anchor:end -->

### Low

<!-- anchor:begin id=low-error-disclosure severity=low tags=error,errors,message,response,http,status,disclosure,leak,notfound,path,handler -->
**A REST error response echoes an internal storage path.** A not-found error on an
unauthenticated endpoint includes the on-disk storage path and the tenant identifier
being looked up. Attacker: T0. Level: low: internal layout is exposed, but no
credential, no configuration and no other tenant's data. Up to medium if the message
includes another tenant's identifiers or values, or confirms a tenant's existence to a
T0 caller.
<!-- anchor:end -->

<!-- anchor:begin id=low-internal-validation severity=low tags=parse,parser,validation,validate,internal,helper,loader,config,unmarshal,decode,inheritance -->
**A controller-internal parser trusts its input.** A helper that parses stored
configuration accepts a malformed value, and that value makes the loader panic at the
next controller start, so whoever can write that storage can wedge the controller.
Every caller is controller code reading controller-written storage. Attacker: T3 only,
who can already stop the controller directly. Level: low: a defence-in-depth gap with
no lower-tier path to the function. Up to medium if a T1 or T2 input reaches the helper
through any route, including a stored value they can write, since a lower tier then
gains a controller-wide availability effect.
<!-- anchor:end -->

<!-- anchor:begin id=low-timing-compare severity=low tags=compare,comparison,timing,constant,equal,equals,bytes,subtle,hmac,token,tokens,registration,verify -->
**A registration token is compared with an ordinary equality check.** The token a
device presents at enrolment is compared to the stored value byte by byte with an
early-exit equality, not a constant-time comparison, so response timing leaks how many
leading bytes matched. Attacker: T0, who can reach the enrolment endpoint. Level: low:
the leak is real but bounded. Each token is single-use and expires in minutes, the
timing signal is a few nanoseconds under network jitter, and recovering one token needs
thousands of attempts per byte inside that window, so no enrolment has been shown to be
forgeable; the residual weakness is that the endpoint's security rests on the token's
lifetime rather than on the comparison. Up to medium if the same comparison guards a
long-lived secret, or the endpoint imposes no rate limit, since the attempts then fit
inside the secret's lifetime.
<!-- anchor:end -->

## Hypothesis form (Issue #4056)

A hypothesis is what the planner writes for a step; a finder lane closes each one it is
given with a disposition (`investigated` / `candidate_found` / `inconclusive` /
`not_attempted`, defined in `schema.py`). Earlier prompt wording asked for "what security
property or vulnerability class is being investigated" -- an `or` that let two planner
models each honestly satisfy the same instruction while writing two different *kinds* of
thing: one wrote falsifiable guesses at named bugs, the other wrote broad properties to
prove. That divergence is not evidence about the models; it is prompt ambiguity.

**The required form, stated once:** a hypothesis is a falsifiable claim about specific
code, paired with the evidence that would confirm or refute it -- never a restatement of
the scope's name, and never a broad security property.

- **Good.** "The certificate expiry check at the point where the chain is validated may
  compare against a clock value that is never re-read per request, so a certificate that
  expired after process start could still validate." Specific, names a concrete mechanism,
  and `required_evidence` can name exactly what to check.
- **Bad.** "Certificate validation is correct." A broad property, not a claim about
  specific code. No single bounded step can close it by reading its own files, so a finder
  lane holding it tends to report `inconclusive` -- the least useful disposition, since it
  neither confirms nor refutes anything.

Every step additionally carries at least one **absence-shaped** hypothesis: what check
should exist among the step's files and does not -- a missing authorization call, an
unregistered revocation path, a handler nobody wired. A step is a list of files that
exist; nothing in it points at what should exist and is missing unless the hypothesis
names it. This is prompt guidance, not a schema rule: `schema.validate_plan_step()` does
not reject a step for lacking one, since forcing a model to invent an absence claim it
does not believe produces noise, not signal.

The enforced copy of this text lives in `.claude/skills/security-review/planner.py`'s
`build_prompt()`, which is what the planner model actually reads; this section is the
same definition for the reader auditing or reviewing it.

## What this document does not cover

- Which tools a lane may run inside a step. That is a harness concern, tracked
  separately.
- The finding schema, defined once in `schema.py`. A lane reports BOTH `cwe`
  (the identifier chosen above, from the closed list) and `vuln_class` (its own
  short prose label). Since Issue #4134 the consolidator keys on the normalised
  `cwe`, and a CONSOLIDATED finding's `vuln_class` carries that same normalised
  class -- each lane's own prose survives on its occurrence and is what a report
  heading shows.
- How the consolidator adjudicates severity when lanes disagree. This document gives
  every lane the same scale; reconciling their ratings is the consolidator's job.
