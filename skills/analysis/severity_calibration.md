---
name: severity-calibration
description: Qualitative rubric for what actually deserves high/critical severity, and an acceptance checklist to apply before rating a finding
---

# Severity Calibration

CVSS gives you a number once you have chosen the metrics. This skill is
about choosing them honestly — deciding what class of issue genuinely
belongs at each severity before you fill in the vector.

Calibrate severity **after** you have established reachability and run
the counterevidence pass, never before. Severity is a conclusion, not an
opening position.

## The Test That Matters

Before rating anything high or critical, ask:

> Would this be accepted as high/critical in serious audit or bug bounty
> triage, by a firm putting its reputation on the line?

If the honest answer is "only if you accept a chain of assumptions", it
is not high. Rate the weakness you proved, not the worst case you can
imagine reaching from it.

## Critical

Reserve for findings where a realistic attacker gets decisive control or
mass data access, with evidence:

- Unauthenticated remote code execution, or command/code execution
  reachable by any user on internet-exposed surface.
- Full authentication bypass, or trivially forgeable authentication
  (accepted unsigned tokens, `alg: none`, signature not verified).
- Mass extraction of other users' or other tenants' sensitive data.
- Compromise of signing keys, control-plane credentials, or credentials
  granting broad infrastructure access.
- Complete cross-tenant isolation failure in a multi-tenant system.

Factors that push a high up to critical: no authentication required,
internet reachable, zero user interaction, wormable/self-propagating,
or the impact spans all tenants rather than one.

## High

- Authenticated RCE, or RCE requiring a common non-privileged role.
- Privilege escalation crossing a real trust boundary (user → admin,
  tenant → tenant, read → write on protected objects).
- Object-level authorization failures exposing or modifying other users'
  sensitive data at scale.
- SQL injection or equivalent injection reaching real data.
- SSRF that demonstrably reaches internal services, cloud metadata, or
  credentials.
- Sensitive credential or PII exposure that an attacker can actually
  reach.

## Medium

- Stored XSS in a limited context, or reflected XSS requiring user
  interaction.
- CSRF on a meaningful state-changing action.
- Authorization gaps on lower-value objects.
- Information disclosure that materially aids a further attack.
- Findings whose high-impact version is blocked by a real constraint you
  confirmed (internal-only exposure, a required privileged role, a
  narrow precondition).

## Low / Informational

- Missing security headers, cookie flag issues, verbose errors.
- Self-XSS, or XSS requiring the victim to paste a payload.
- Open redirect with no credential or token leakage.
- Rate-limiting and enumeration issues without a demonstrated impact.
- Defense-in-depth gaps with no reachable exploitation path.

## Usually NOT High or Critical

These are over-rated constantly. Each needs unusual, demonstrated
circumstances to exceed medium:

- Self-XSS and clickjacking on non-sensitive actions.
- Missing headers, cookie attributes, TLS configuration nits.
- Open redirect on its own.
- Theoretical memory-safety issues with no reachable attacker input.
- "Could matter if chained with several unproven assumptions."
- Anything already requiring admin, shell, or physical access — if the
  attacker already has that, the finding adds little.
- Session-management weaknesses that require the attacker to already
  hold a victim secret (a stolen cookie, an intercepted link). The
  acquisition of that secret is not free; unless the *same* finding shows
  how to obtain it, this is usually low/medium.
- Enumeration that only confirms an account, domain, or version exists.

## Downgrade, Don't Delete

A finding that turns out to be constrained gets a lower severity — not a
silent drop. Internal-only reachability, a required privileged role, or a
narrow precondition are all reasons to reduce severity and say so in the
report. They are not reasons to withhold the finding.

Equally: missing evidence about deployment or exposure lowers your
**confidence**, not the severity floor. Do not treat "I could not confirm
this is internet-facing" as if it were "this is internal-only".

## Acceptance Checklist for High / Critical

All of these must be true. If any is not, drop a level:

- [ ] The attack path is realistic and in scope — not a lab-only
      condition, not dependent on an unproven prior compromise.
- [ ] The attacker position required is one an attacker can actually
      obtain, and the CVSS `privileges_required` / `attack_complexity`
      reflect that honestly.
- [ ] The impact is material and demonstrated, not asserted — `C:H` /
      `I:H` mean proven broad or systemic read/write, not one record.
- [ ] The counterevidence pass found no constraint that meaningfully
      limits exploitation, or you have explained why the constraint does
      not hold.
- [ ] You have concrete evidence of reachability, not an assumption
      about how the application is deployed.
- [ ] You would defend this rating in a client debrief.

## Output

Severity still comes from the CVSS vector — this rubric decides which
vector is honest. When your intuitive rating and the computed CVSS
severity disagree, re-examine the metrics: usually one of
`privileges_required`, `attack_complexity`, or the impact triad was set
optimistically. Fix the metric, do not override the result.

## How to Apply in mr.robot

Use the 6-gate acceptance checklist above before setting the `severity` field in `arcade_post_finding`. The checklist is the gate, not a suggestion — if any item is unchecked, drop one severity level.

**Anti-inflation is the default.** When uncertain between two severity levels, start at the lower one and escalate only with explicit evidence. Inflated severity in a finding log degrades the signal-to-noise of the entire engagement and wastes follow-up time.

**HTB machines are a false positive trap.** Scanning tools frequently fire on:
- Version-based CVE matches where the specific patch level wasn't checked
- Default-credential templates where the credentials were changed
- Misconfig templates where the "misconfiguration" is intentional CTF scenery
- Headers and cookie flags that are cosmetically wrong but not exploitable on a static lab box

For every nuclei/nmap/nikto finding, ask: did I send the actual exploit payload and observe the actual impact, or did I observe a pattern that *suggests* the vulnerability might exist? The former can be high/critical. The latter is at most medium with low confidence until you verify.

**Privilege escalation in HTB context:** "user → root" on an HTB machine is the goal, but privilege escalation findings within the box (e.g., sudo misconfiguration, SUID binary, writable cron) should be rated based on what trust boundary they actually cross, not based on the excitement of the path. A finding that requires you to already have a shell is not critical — it is high at most, often medium, depending on the privilege delta and required starting position.

**Chain-dependency inflation:** If a critical rating depends on a chain of two or more unproven steps, rate each step independently at its own honest severity. Document the chain in `notes` as a potential escalation path, not as a single critical finding.
