# Secure Development

Platform-specific security guidance and iterative code review for smart contracts **during development**. Every skill in this plugin is explicitly positioned as a development-time partner — helping developers build correctly the first time so that subsequent audits find fewer issues. None of these skills replace a formal audit, and each has an explicit handoff signal for when an audit is what the user actually needs.



## Skills

The two skills cover meaningfully different Cardano development workflows and adopt review styles appropriate to each:

### `/cardano-plutus` — Plutus Security And Performance Advisor

Security best-practice guidance and iterative code checks for Cardano Plutus validators, minting policies, staking scripts, and on-chain designs written in Haskell/Plutus.

**Three usage modes**:
- *Development security guidance* — proactive architecture advice for projects still being built
- *Development code check* — invariant-driven analysis of concrete artifacts during development iteration
- *Performance analysis* — structural cost-driver analysis (static hypothesis only; measured ExUnits require off-chain tooling)

**Coverage**:
- Comprehensive within development-guidance scope: spending validators, minting policies, cross-script (validator + policy) invariants
- Basic: staking scripts (withdrawal and certificate authorization)
- Frame-level only: governance scripts (CIP-1694) — additional domain-specific review required
- Cardano-native pitfalls: min-ADA, staking credentials, Value semantics
- Plutus V1, V2, and V3 awareness


### `/cardano-aiken` — Aiken Security Advisor

Security and performance review for Cardano smart contracts written in Aiken, with **fuller Conway-era governance coverage** than the Plutus advisor.

**Four review scopes** (activated via a routing gate; multiple can be active simultaneously):
- *Design Review* — for design descriptions, architecture sketches, and pseudocode
- *Developer Security Review* — for runnable Aiken code or PR diffs
- *Interface Review* — when off-chain transaction assembly is provided alongside on-chain code; reviews the on-chain/off-chain dependency contract, including batcher and aggregator trust
- *Performance Analysis* — structural or hypothesis-level; upgrades to measured when `aiken bench` output is provided

**Coverage**:
- All handler types: `spend`, `mint`, `withdraw`, and full governance handlers — `publish`, `vote`, `propose`
- Validator parameters, env modules (`env/default.ak` etc.), and `aiken.toml` `[config]` constants reviewed for security impact
- Plutus V2 vs V3 detection with version-appropriate guidance
- Oracle scope boundary is explicit: on-chain oracle consumption is reviewed; oracle data-source integrity is flagged as out of scope

**Additional output**: every review includes a Pre-Audit Readiness section and an explicit handoff signal to an audit skill when criteria are met.

## Shared Principles

All skills in this plugin share a set of ground rules. The Cardano skills use `❗/⚠️/💡` labels with severity and confidence ratings, and the underlying discipline is consistent:

- **Development-time positioning, not audit.** Every skill helps developers ship correctly the first time; none replace formal audit. Each has an explicit handoff signal that recognizes when an audit-shape request has come in and declines to drift into it.
- **Evidence-grounded findings.** Issues are raised only when a concrete code path or stated invariant supports them. Absence of a common check is never sufficient by itself to claim a vulnerability.
- **No invented logic.** Skills never assume the behavior of off-chain components, helper functions, or protocol invariants not present in the submitted material. When a conclusion depends on unseen context, the skill says exactly what would confirm or falsify it.
- **Scope honesty.** Each skill declares what it covers, what it does not, and where a dedicated audit or domain-specific review is required. Partial coverage with clear boundaries is preferred over claimed-but-superficial full coverage.
- **Minimal, idiomatic fixes.** Remediations stay close to the reviewed codebase's style and the platform's idioms. When surrounding code is insufficient to produce a concrete fix, the skill says so and asks for the specific missing piece rather than offering generic advice.

---

## Example Workflow

1. Install the plugin (see installation above).
2. Invoke the skill matching your platform (`/cardano-plutus` or `/cardano-aiken`) while designing the architecture — use design-mode / guidance-mode to plan before writing code.
3. Switch to the skill's code-review mode as concrete code is written, iterating on findings.
4. Before submitting for formal audit, we recommend resolving all `❗` findings and addressing `⚠️` items with explicit documentation where they represent accepted assumptions.
5. For Aiken projects, confirm the Pre-Audit Readiness criteria are met before handoff.
