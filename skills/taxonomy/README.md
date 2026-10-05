# taxonomy

Machine-walkable attack matrices. Where the prose skills teach *how to reason*,
these express the same offense as config an orchestrator can iterate cell by
cell.

| File | What |
|---|---|
| [`prompt_injection_taxonomy.yaml`](prompt_injection_taxonomy.yaml) | LLM prompt injection as four axes — **intents × techniques × evasions × outcomes** — after the public Arcanum taxonomy, mapped to OWASP LLM01:2026. |

## Why config, not prose

An mr-robot campaign against an LLM target can load this file and walk the
cells — pick an *intent*, a *technique* to deliver it, zero or more *evasions*
to clear a guardrail, and an *outcome* that proves real impact — instead of
re-deriving the attack space per engagement. The prose skills remain the
authority on judgment and validation:

- [`../vulnerabilities/llm_prompt_injection.md`](../vulnerabilities/llm_prompt_injection.md)
- [`../vulnerabilities/agentic_system_security.md`](../vulnerabilities/agentic_system_security.md)
- [`../technologies/llm_applications.md`](../technologies/llm_applications.md)

## Two rules carried in the data

- **Non-determinism.** LLM targets are stochastic; one try proves nothing.
  Each `(technique × evasion)` cell is run `attempts.default` (10) times —
  5 quick, 15 thorough — before a true/false-positive verdict.
- **Outcome over chatter.** A cell is a finding only with an `outcomes`
  evidence artifact captured *outside* the model transcript (a tool-invocation
  log, an outbound request to a sink, a changed record). A compliant-sounding
  reply with no sink is a candidate, not a finding.

## Extending

The `evasions` axis is a high-signal floor, not the whole universe — the public
taxonomy enumerates 170+. Add rows in place, keeping each row's shape
(`id`, `name`, `aka`, `idea`, `samples`). The `mr-robot` injection regression
(`server/tests/test_injection_defense.py`, ADR-0017) can point `MR_ROBOT_TAXONOMY`
at the evasion list to widen its defensive corpus from the same source.
