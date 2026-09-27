# CFGMS threat scenarios

What a sweep looks for. Companion to [`methodology.md`](methodology.md).

## Editing rules

- One scenario per `scenario:begin` / `scenario:end` block.
- `id` is permanent. Retire, never reuse.
- `tier` is a `methodology.md` attacker tier: `T0`, `T1`, `T2`, `T3`, `P`.
- `boundary` is one of `internet-listener`, `steward-to-controller`, `tenant-to-tenant`,
  `publisher-to-host`, `controller-to-steward`, `cross-cutting`.
- A bold requirement line, then **Check**. State what must hold, never current behaviour: no
  status, dates or issue numbers.
- Scenarios do not change when code changes.
- Name packages, not line numbers. Name no third-party vendor. Give no exploit detail.

---

## Boundary 1 — internet to REST/gRPC listener

<!-- scenario:begin id=TS-01 tier=T0 boundary=internet-listener -->
**Every administrative route requires authorisation, and the permission names the object the handler touches.**

- **Check:** in the controller's HTTP API package, routes registered without the permission
  wrapper, or wrapping a resource or action the handler does not operate on.
<!-- scenario:end -->

<!-- scenario:begin id=TS-02 tier=T0 boundary=internet-listener -->
**No connection is usable unless the peer's certificate chain verified.**

- **Check:** every client-side TLS configuration in the certificate package and the QUIC transport
  adapter — verification callback, minimum version, and whether any error branch still yields a
  usable connection.
<!-- scenario:end -->

<!-- scenario:begin id=TS-03 tier=T0 boundary=internet-listener -->
**Untrusted request content is validated before its first use.**

- **Check:** for each controller handler, whether a decoded value reaches a file path, store key,
  tenant lookup or command argument before the protobuf validators run on it.
<!-- scenario:end -->

---

## Boundary 2 — enrolled steward to controller

<!-- scenario:begin id=TS-04 tier=T1 boundary=steward-to-controller -->
**A registration token enrols exactly what it was issued for, exactly once.**

- **Check:** in the registration package and its stores — is consumption atomic with use, or after
  it? Is expiry enforced at redemption or only at issue? Can one token yield two identities? Does
  approval compare the approving identity against the one recorded at request time?
<!-- scenario:end -->

<!-- scenario:begin id=TS-05 tier=T1 boundary=steward-to-controller -->
**A steward receives only the secret material addressed to it.**

- **Check:** in the configuration transport handler, fleet storage and secrets providers — does the
  response scope come from the verified connection identity or from the request? Does inheritance
  pull an ancestor's secrets into a descendant's bundle? Is decrypted material cached, and under a
  key the caller controls?
<!-- scenario:end -->

<!-- scenario:begin id=TS-06 tier=T1 boundary=steward-to-controller -->
**Steward-reported data is neutralised before the controller records it.**

- **Check:** controller-side log and audit calls where a steward-supplied value, or an error
  wrapping one, reaches the message unsanitised.
<!-- scenario:end -->

---

## Boundary 3 — tenant admin to another tenant

<!-- scenario:begin id=TS-07 tier=T2 boundary=tenant-to-tenant -->
**Tenant scope comes from the authenticated principal and compares by path segment.**

- **Check:** scope comparisons using a string prefix on a joined path rather than segment equality,
  which makes `root/msp-a` match `root/msp-ab`. In the fleet selector, whether a parsed tenant
  prefix authorises, or only filters inside a scope the principal already holds. The second is
  correct.
<!-- scenario:end -->

<!-- scenario:begin id=TS-08 tier=T2 boundary=tenant-to-tenant -->
**Configuration inheritance resolves root to leaf in every path that resolves it.**

- **Check:** trace one key through every resolution path in the tenant stores and config
  resolution. Which end wins on conflict, and is it the same end in every path? One path
  disagreeing is the defect.
<!-- scenario:end -->

---

## Boundary 4 — module publisher to the hosts that run the module

<!-- scenario:begin id=TS-09 tier=P boundary=publisher-to-host -->
**Signature verification fails closed, and no pushed value can disable it.**

- **Check:** in the module trust package and the steward-side trust plumbing — every success return
  in verification, reachable without a signature having been checked? An absent or empty signature
  treated as valid? Are weak or malformed publisher keys refused before use? The bypass mode
  selectable by anything but local development configuration?
<!-- scenario:end -->

<!-- scenario:begin id=TS-10 tier=P boundary=publisher-to-host -->
**A host never accepts a module older than the one it already runs.**

- **Check:** in bundle installation and the controller's module cache and approval path — is there
  an ordered version comparison at install? A signature check is not a version check. Can the cache
  serve a bundle older than the one a host runs?
<!-- scenario:end -->

<!-- scenario:begin id=TS-11 tier=T3 boundary=publisher-to-host -->
**Publisher signatures reach the steward intact; the controller never re-signs.**

- **Check:** any controller-side path that constructs a signature rather than copies one. Whether
  the publisher identity compiled into the steward binary is read from anywhere writable at runtime.
<!-- scenario:end -->

---

## Boundary 5 — controller to steward

<!-- scenario:begin id=TS-12 tier=T2 boundary=controller-to-steward -->
**One action reaches only what the principal is authorised for, and a bounded number of endpoints.**

- **Check:** in the fleet selector and the operation path that applies a resolved set — at which
  step is the set intersected with the caller's scope? Filtering after resolution is the defect. Is
  there any ceiling on one operation, or staging between a subset and the remainder? The finding is
  an absent bound; no handler will look wrong.
<!-- scenario:end -->

<!-- scenario:begin id=TS-13 tier=T2 boundary=controller-to-steward -->
**A steward refuses a configuration that would sever its own control-plane connection.**

- **Check:** in the convergence loop and the rollback feature — can a converged configuration
  disable the transport needed to receive the next one? Is the refusal explicit? Does rollback
  require the controller to be reachable? Findings here are in scope even though `methodology.md`'s
  resource-exhaustion class excludes a same-tenant actor.
<!-- scenario:end -->

<!-- scenario:begin id=TS-14 tier=T1 boundary=controller-to-steward -->
**Nothing a local unprivileged user controls influences what the steward executes.**

- **Check:** in the script module and the steward client's staging path — staging directory
  permissions, the window between hash verification and execution, whether any path is opened
  without rejecting symlinks, and whether any argument reaches an interpreter inside a composed
  string rather than as its own argv element.
<!-- scenario:end -->

---

## Cross-cutting

<!-- scenario:begin id=TS-15 tier=T2 boundary=cross-cutting -->
**The principal that writes an audit entry cannot alter or remove it.**

- **Check:** in the audit manager's drain and batch-write path, its redaction rules, and the audit
  stores — can the writing principal delete or update an entry through any store path? What happens
  to a buffered batch on unclean shutdown? Does redaction ever remove actor identity?
<!-- scenario:end -->
