---
issue: 454
---

# Issue #454 — Pre-commit secret scan for field logs: stop NTRIP config reaching a public repo

## Issue Review
**Status**: complete
**When**: 2026-08-24 14:54 -04:00
**By**: Claude Code Agent (Claude Sonnet)

**Issue**: #454
**Comment**: (best-effort post follows this entry; not recorded inline)
**Scope verdict**: needs-more-detail

### Findings

**The problem statement is accurate and confirmed against the repo.** Read the
2026-08-03 leak directly from history (`git show 6b963ce`): a public routable
IPv4 address, a non-standard port, a mountpoint string, and a username were
committed in the clear in `docs/logs/2026/2026-08-03_salmon_logs.md`. The
2026-08-21 occurrence's own log entry, still in the working tree, corroborates
the second leak and shows it was caught and redacted before merge (the current
text reads `host (redacted):8005` / `user (redacted)`). `docs/bizzyboat_network.md`
does state that credentials and public IPs belong only in the private
`ccomjhc_project11` repo.

**Quantifying the false-positive surface (the issue's own caveat, checked):**
`docs/logs/**` currently contains 133 IPv4-shaped strings across 97 files.
Classified programmatically (RFC1918 / loopback / link-local / reserved
excluded), only 5 are outside that allowlist: `1.1.1.1`, `8.8.8.8` (public DNS
resolvers, named as such in `bizzyboat_network.md`), `100.64.0.1` (CGNAT,
RFC 6598 — a legitimate Starlink-path address, not RFC1918 but also not a
secret), and two garbled non-IP numbers (`1.1.0.0`, `3.2.0.0`, likely
version/build strings misparsed by a bare regex — a fixture-writer's warning
sign for a naive detector). **Zero remaining true positives** — the one real
secret IP (`70.88.225.204`) is already redacted in the working tree. So an
IPv4 detector with an RFC1918+loopback+multicast allowlist would have a very
low false-positive rate here — this part of the proposal holds up.

**The "known caster hostname / mountpoint" detection axis does not hold up.**
`macorsrtk.massdot.state.ma.us` (the MaCORS caster host) and its mountpoint
names appear, deliberately and repeatedly, in `docs/bizzyboat_gps_config_2026-04-02.md`,
`docs/bizzyboat_deployment_log.md`, `docs/izzyboat_network.md`, **and inside
`docs/logs/` itself** (`docs/logs/2026/2026-04-27_dev_logs.md`,
`docs/logs/2026/2026-08-21_gabby_logs.md` line 30, which is the *same* log
entry that redacted the Delaware caster three lines above it). MaCORS is
public state infrastructure; publishing its host/port/mountpoint isn't the
leak — the account name adjacent to it was. A hostname/mountpoint-pattern
hook would flag already-accepted, already-merged content and fail the issue's
own acceptance criterion ("existing logs pass without modification"). The
`user`/`username`/`password`-adjacent-to-a-value axis is the one that
actually distinguishes the two real leaks from the legitimate MaCORS
references, and should be scoped tighter for the mountpoint/hostname case (or
dropped) rather than assumed alongside the IP-address axis as if they carried
equal risk.

**The pre-commit layer would not have caught either real incident, and this
is directly evidenced in the repo's own field logs, not an inference:**
- `docs/logs/2026/2026-08-06_gabby_logs.md` (13:14 and 13:15 entries): "this
  clone has NO pre-commit hook installed... RECOMMEND running 'pre-commit
  install' in this clone" — and at wrap-up (23:49) the operator explicitly
  **declined** to track installing it.
- `docs/logs/2026/2026-08-20_gabby_logs.md` (10:01, second entry):
  "`unh_echoboats_project11` on gabby still has NO pre-commit hook installed
  ... still recommended, still not done" — one day before the 2026-08-21
  leak, on the exact host (gabby) that produced it.
- `docs/logs/2026/2026-05-19_salmon_logs.md` / issue
  [rolker/unh_echoboats_project11#143](https://github.com/rolker/unh_echoboats_project11/issues/143):
  salmon's workspace clone had no pre-commit hook installed either, as of
  2026-05-19 (project-repo clone status on salmon specifically as of
  2026-08-03 wasn't separately re-confirmed, but nothing in the log record
  suggests it was fixed).
- `docs/logs/2026/2026-08-19_pandy_logs.md` (602): pre-commit **cannot even
  run** on pandy — `python3.12-venv` isn't installed.

So a pre-commit-only implementation would be exactly the "third manual
catch, closer to chance than it should be" the issue is trying to get away
from: the rule would exist in `.pre-commit-config.yaml` but not execute on
the hosts that produced both incidents. This also isn't a novel objection —
it's a direct application of [ADR-0004](../../../docs/decisions/0004-enforcement-hierarchy-for-agent-compliance.md)
and [ADR-0005](../../../docs/decisions/0005-layered-enforcement-strategy.md), already in this
repo's own governance: *"CI + branch protection is the enforcement layer...
If a rule isn't in CI, it's a suggestion, not a rule"* and *"Never implement a
rule only in a framework hook."* Pre-commit is explicitly the local
fast-feedback layer, "bypassable, complements CI rather than replacing it" —
here it isn't even installed on the hosts that need it, which is worse than
bypassable.

**What actually caught both leaks, and is a viable CI-layer candidate:** both
were caught during GitHub PR review (Copilot) — the 2026-08-03 one in normal
review, the 2026-08-21 one during the `/import-field-changes` reconciliation
PR (#453). Field commits land on the gitcloud remote directly (field mode)
and only reach GitHub — and this repo's `.github/workflows/ci.yml` — when a
reconciliation PR opens against `jazzy`. `ci.yml` currently only builds and
tests; it has no secret-scan step. A CI check on `pull_request` (which fires
on every reconciliation PR, is non-bypassable per ADR-0005, and doesn't
depend on any field host's local tooling) would be a mechanism instead of
luck, and would still be reinforced by a `.pre-commit-config.yaml` entry for
fast local feedback on dev clones where hooks are reliably installed.

**Acceptance-criteria caveat:** "The 2026-08-03 and 2026-08-21 strings are
both in the test fixtures" needs a scoping note before implementation. The
2026-08-03 secret is already in public GitHub history (`6b963ce`), so
reproducing its shape in a fixture doesn't create new exposure. The
2026-08-21 secret, per the issue's own account, was redacted **before**
merge via history rewrite — it may never have reached public GitHub history
at all. Committing the literal real value into a new test-fixture file now
would be a fresh, first-time public exposure of exactly the kind this issue
exists to prevent, and would also violate this dispatch's own instruction
never to write credentials/IPs into files or commits. Fixtures should use
synthetic values with the same shape (public IPv4 + port + mountpoint +
username pattern) rather than the literal historical secrets, particularly
for the 2026-08-21 case.

### Principle Alignment

| Principle | Status | Notes |
|---|---|---|
| Enforcement over documentation | Action needed | Issue proposes pre-commit only; ADR-0004/0005 require CI as the load-bearing layer, and pre-commit is confirmed not installed on the field hosts that produced both incidents |
| A change includes its consequences | Watch | If the durable home becomes `ros2_agent_workspace`'s `.agent/templates/pre-commit-config.yaml` per the issue's own scope note, that's explicitly deferred follow-up work, not silently dropped — fine as scoped |
| Only what's needed | OK | Scoping to `docs/logs/**` first, proving it in one repo before templating, matches "improve incrementally" |
| Test what breaks | Watch | Acceptance criteria call for literal historical secrets in fixtures — see caveat above; needs revision to synthetic values before implementation |
| Capture decisions, not just implementations | OK | Issue documents the two incidents and their catch mechanism clearly |

### ADR Applicability

| ADR | Triggered | Notes |
|---|---|---|
| 0004 — Enforcement hierarchy | Yes | Pre-commit-only violates "multiple layers, no single layer sufficient" as currently scoped |
| 0005 — Layered enforcement | Yes | "If a rule isn't in CI, it's a suggestion" — directly applicable given field hosts don't run pre-commit for this repo |
| 0009 — Python package management | Watch | If `detect-secrets` or `gitleaks` needs a Python venv, note pandy's `python3.12-venv` gap (docs/logs/2026/2026-08-19_pandy_logs.md:602) already blocks pre-commit there entirely — another argument for CI as the primary layer |

### Consequences

- A CI-side check touches `.github/workflows/ci.yml`, which isn't mentioned in the issue's proposal (pre-commit only) — should be added to scope.
- If a detector/allowlist config is added, `.agent/templates/pre-commit-config.yaml` and any generic workspace CI template are the deferred, explicitly-out-of-scope follow-up per the issue's own "prove it here first" note — fine, but worth confirming a follow-up issue gets filed rather than silently forgotten once this lands.

### Actions
- [ ] Revise the proposal to include a CI-side check (on `pull_request` against `jazzy`, where reconciliation PRs land) as the primary, load-bearing layer per ADR-0004/0005 — not pre-commit alone, since pre-commit is confirmed uninstalled on the hosts (gabby, salmon, pandy) that produced or could produce these leaks.
- [ ] Narrow or drop the "known caster hostname / mountpoint" detection axis — it would flag already-accepted MaCORS references throughout `docs/logs/` and other docs; the `user`/`username`/`password`-adjacent pattern is the axis that actually distinguishes the two real leaks.
- [ ] Revise the acceptance criterion on test fixtures to use synthetic values with the same shape as the two incidents, not the literal historical secrets — the 2026-08-21 string was never in public GitHub history and committing it now for a fixture would be a first-time exposure.
- [ ] Confirm during planning whether pre-commit should still be added as a secondary fast-feedback layer for dev clones (where hooks are reliably installed) even though it can't be the sole mechanism.
