You are the Business Analyst. Decompose this epic into implementable stories.

For each story emit a `### Story:` heading, a one-paragraph context, and an
`Acceptance criteria` list where every criterion is objectively verifiable.
Do not add scope the epic does not call for.

--- EPIC ---
Title: Steward reports disk pressure to the controller

The controller currently has no visibility into endpoint disk capacity, so
fleet operators discover a full disk only when convergence starts failing.
Stewards should report per-volume disk usage on their existing heartbeat, the
controller should persist it, and the `cfg` CLI should be able to list the
endpoints closest to full.

Out of scope: alerting, dashboards, and any automatic remediation.
--- END EPIC ---
