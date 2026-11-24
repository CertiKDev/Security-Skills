# Validating CashScript Findings Before Reporting

Independent verification of CashScript audit findings regularly changes first drafts, and the errors fall into a few repeatable classes. Run every candidate finding through this file before it reaches `findings.md`.

## 1. Prove the transaction, not the line

A candidate becomes a finding only after a full trace:

1. Write the concrete transaction: every input (contract, function, index, token), every output (script, token, commitment, amount, value), and the unlocking arguments.
2. Run every script in that transaction in your head, including the co-spent contracts, and say why each one passes.
3. Try to refute it. The most common refutation is a sibling contract in the same transaction that pins the output or index the finding assumed was free.

Anything short of this goes to a "leads" list, not to the report.

## 2. Mistakes that produced wrong findings, and the check that catches each

| Mistake | Check |
|---|---|
| An output or path assumed unconstrained, but a co-spent contract pins it (for example a sidecar that must re-create itself when the primary is present) | Read every script that runs in the transaction shape, not only the one under review |
| The attacker in the scenario needs a credential they do not hold (a victim's vault needs the victim's key) | For each step, name who signs or holds which token |
| "The builder keeps the excess" when the builder actually tops up a deficit | Recompute the value flow per actor, inputs minus outputs |
| A lag or stall named as the attack's source also blocks the attacker's own step | Check that the precondition does not disable the exploit |
| "Stakers lose" on a path where stakers burn the debt themselves | Name the loser per path; paths that look alike can differ |
| A category-only check assumed to require an NFT or a capability | A bare category also matches FT-only and empty-commitment NFTs |
| Read-only inputs assumed | BCH has none; reading a contract means spending and re-creating it |
| Mempool front-running or "any relay can redirect" assumed | BCH relays first-seen without replace-by-fee; state the miner or entry-node assumption |
| Commitments capped at 40 bytes | 128 bytes since 2026-05-15 |
| "This overflows and fails" | No overflow since BigInt (2025-05-15); only `toPaddedBytes` width and token amount limits remain |
| Only one transaction shape checked for a leak | Re-check every function that spends the same capability; one leak pattern usually appears in several functions |
| "Permanent", "never", "perpetual" | Look for the self-healing path, the fallback, or the unanimous-exit escape before using an absolute |

## 2b. Mistakes that wrongly rejected or downgraded real findings

Refutation cuts both ways. These rejections looked sound and were wrong.

| Rejection | Why it fails |
|---|---|
| "Ordering rules only allow moves to a strictly better position, so a chain of moves is short" | The attacker can prepare the chain: a ladder of their own positions, or a permissionless refresh that makes a prepared position eligible mid-claim |
| "Anyone can settle or cancel, so the counterparty is protected" | Name who else has the incentive and timing. If the attacker holds both sides, or the victim is passive, nobody acts |
| "A documented behaviour, so not a finding" | Check the documented bound against the code. Documentation that states a narrower exposure than the code allows is a finding |
| "No attacker profits, so Minor" | Permanent loss or freeze of user funds reached by ordinary use is impact without an attacker |
| "Depends on an unknown deployment parameter, so Minor" | Rate at the realistic deployment range, state the condition, and give the severity on each side of it |

## 3. Recommendations must be enforceable and must not break something else

| Bad recommendation pattern | Why it fails |
|---|---|
| "Reject X after time T", "only before the boundary", "must use the latest message" | Scripts prove only lower bounds on time; the spender sets `tx.locktime` early. No script knows which oracle message is latest |
| "Read the collector (or pool) state" | No read-only inputs; adding the singleton to every transaction serializes users and makes the function depend on its availability |
| A fix another line already enforces | Grep for the invariant before recommending it; a no-op fix signals a misread |
| A clamp or bound that still admits the scenario in the finding | Re-run the scenario against the proposed fix |
| A fix that divides by a quantity that can be zero, or strands positions shrunk by losses | Run the edge cases (zero, one position, all exited) against the fix |
| Exempting small operations | Reopens "open small, then grow large" |
| A new state field placed mid-layout | Every reader using `split(k)[1]` or fixed offsets breaks; list each reader |
| Moving work into a "same transaction as" rule | Couples liveness of two subsystems |

## 4. Severity calibration

- Severity follows impact times likelihood. Write the counterfactual: would the loss have happened with an honest oracle, a timely keeper, or market conditions alone?
- If the attacker cannot create the precondition (a keeper lag, an oracle outage), likelihood is low and the finding is usually Minor unless the impact is large.
- A liveness failure that freezes user funds or a core function with no recovery path is at least Medium when ordinary use can reach it within the system's expected life, or when griefing it costs less than the value frozen. A permanent, compounding loss to a class of users (orphaned rewards diluting every later staker) is at least Medium.
- A free option handed to one side of a trade (locked price, delayable settlement) is at least Medium when its value is a material fraction of the amount at realistic volatility.
- State conditional severities explicitly ("Major if the deployed supply is below 1e8 units").
- When a check covers more functions than first thought, raise scope and severity; reviewers understate as often as they overstate.
- An untested network assumption (relay behaviour, miner policy) caps the rating until a live test confirms it.

## 5. Numbers

- Recompute every figure with a script and keep the script.
- Label units: per period or per year, simple or log return, base units or display units.
- Prefer exact suprema to sampled maxima.
- Check byte sizes against real serialization (token prefix included).

## 6. Citations

- Cite `file:line` from a per-file listing. Never number lines from a concatenation of several files.
- Cite the executable line, not a comment above it.
- Verify every cited line exists and says what the finding claims before writing.

## 7. Deduplicate by root cause

Merge findings that share one root cause and one fix, even if found in different functions. Split one finding into two when the parts need different fixes. When a later review finds a new angle on a known issue (wider scope, a broken recommendation, a wrong line), record it as an amendment to that issue rather than a new finding.
