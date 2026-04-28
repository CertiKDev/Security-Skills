# Aiken Performance Optimization Reference

Cardano meters script execution with CPU and memory budgets and also constrains transaction size, but the exact break-even points depend on:
- current protocol parameters
- Plutus version and ledger language version
- Aiken compiler version and stdlib version
- transaction composition
- datum and value sizes

Treat this document as a benchmark-first and version-sensitive reference, not a list of guaranteed wins.

Optimization discipline:
1. Preserve correctness first. Never weaken validation to save budget.
2. Prefer measured claims over stylistic guesses.
3. Distinguish architectural wins from micro-optimizations.
4. Call out version-sensitive advice explicitly.
5. When in doubt, benchmark with representative inputs before recommending a change.
6. Never replace logic that proves uniqueness, exact cardinality, authority, or canonical-state identity with a cheaper shortcut unless that invariant is provably irrelevant.

Quick triage:
- Repeated scans over inputs, outputs, or values: start with OPT-2, OPT-3, OPT-4, OPT-13.
- Large datum or state makes validation expensive: start with OPT-6, OPT-9, OPT-10, OPT-11.
- Script-size or witness-size pressure: start with OPT-7, OPT-8, OPT-11.
- Advice depends on compiler / stdlib / ledger behavior: start with OPT-5 and OPT-12.
- Use this index to choose a starting point, then benchmark before turning a heuristic into a stronger recommendation.

---

## OPT-1: Benchmark Before Claiming a Win

**Why it matters:** Aiken has first-class benchmarks, so optimization advice should be grounded in measured CPU / memory cost whenever possible.

**Example:**
```aiken
// `sample_state` must be a Sampler<State>, i.e. fn(Int) -> Fuzzer<State>,
// as provided by aiken-lang/fuzz. A plain Fuzzer<State> will not compile here.
bench validate_state_bench(state: State via sample_state) {
  validate_state(state)
}
```

**Guideline:**
- Use `aiken bench` for hot-path hypotheses
- Use realistic samplers that grow transaction or datum complexity
- Prefer benchmark evidence over intuition when the code is non-trivial
- Confirm `bench` syntax and sampler types against your project's Aiken version before use

**Tool limitation note:** This skill cannot execute `aiken bench` directly. Without
user-provided benchmark output, all performance claims default to **Structural** or
**Hypothesis** confidence. If the user provides `aiken bench` results as input, those
can be consumed as **Measured** evidence.

---

## OPT-2: Keep Each Handler Local to the Fields It Actually Needs

**Why it matters:** Many validators do extra work on every path by scanning outputs, decoding data, or traversing values even when a branch only needs signatories or minting data.

**Before:**
```aiken
when redeemer is {
  AdminAction -> heavy_full_transaction_review(self)
  Withdraw(amount) -> validate_withdraw(state, amount, self)
}
```

**After:**
```aiken
when redeemer is {
  AdminAction ->
    list.has(self.extra_signatories, admin_key_hash)

  Withdraw(amount) ->
    validate_withdraw(state, amount, self)
}
```

**Profiling note:** This is usually a good first cleanup, but still treat the savings as a benchmark question.

---

## OPT-3: Prefer Single-Pass Traversals on Hot Paths

**Why it matters:** Repeated `filter`, `find`, `map`, and `length` chains can cause multiple passes over attacker-controlled collections.

**Before:**
```aiken
let matching_outputs =
  list.filter(self.outputs, fn(output) { pays_beneficiary(output) })

expect Some(output) = list.at(matching_outputs, 0)
```

**After:**
```aiken
expect Some(output) =
  list.find(self.outputs, fn(output) { pays_beneficiary(output) })
```

**Profiling note:** This is a heuristic. It matters most when the same collection is inspected repeatedly or transactions can get large.
**Semantic note:** Only replace a multi-step traversal with `find` when the protocol truly needs existence or first-match semantics. If the code must prove uniqueness, exact count, or "all matching outputs satisfy X", keep the stronger logic.

---

## OPT-4: Reuse Decoded / Located Data Instead of Re-Finding It

**Why it matters:** If you already located `own_input`, a successor output, or a decoded datum, reusing it is usually cheaper and clearer than re-running the same search or decode.

**Before:**
```aiken
let signed = list.has(self.extra_signatories, owner)
let own_input =
  list.find(self.inputs, fn(input) { input.output_reference == own_ref })

// later, scan self.inputs again for the same reference
let own_input_again =
  list.find(self.inputs, fn(input) { input.output_reference == own_ref })
```

**After:**
```aiken
let signed = list.has(self.extra_signatories, owner)
expect Some(own_input) =
  list.find(self.inputs, fn(input) { input.output_reference == own_ref })

use_own_input(own_input, signed)
```

**Profiling note:** This is rarely controversial. The main question is how much it matters on the target transaction shape.

---

## OPT-5: Keep Traces Out of Production Builds

**Why it matters:** Aiken traces are excellent during development, but they add overhead when preserved.

**Development workflow (version-sensitive — confirm for your Aiken version):**
- In many versions, `aiken check` preserves traces by default
- In many versions, `aiken build` strips traces by default

**When measuring:**
- Use `aiken check --trace-level silent` if you want test-like execution without trace overhead
- Use `aiken build --trace-level verbose` only when you intentionally want traces in final artifacts

**Tradeoff:** Traces help debugging and review. Budget measurements should note whether traces were present.
**Version note:** Trace defaults and `--trace-level` behavior have changed across Aiken releases. Always confirm the behavior for your specific Aiken version before making toolchain-specific recommendations or budget measurements.

---

## OPT-6: Keep Decoding and Shape Assertions Local

**Why it matters:** Repeated `expect`-based decoding of the same datum or reference datum can duplicate work and make hot paths noisier than necessary.

**Before:**
```aiken
expect Some(raw) = datum_opt
expect state: State = raw

let owner_ok = valid_owner(state.owner)
expect state_again: State = raw
let phase_ok = valid_phase(state_again.phase)
```

**After:**
```aiken
expect Some(raw) = datum_opt
expect state: State = raw

let owner_ok = valid_owner(state.owner)
let phase_ok = valid_phase(state.phase)
```

**Guideline:** Decode once, then operate on the typed value. Keep repeated conversions or repeated datum lookups out of loops and hot branches.

---

## OPT-7: Minimize Minting Policy Dependency Surface

**Why it matters:** Policies that drag in broad state validation, large datum types, or unrelated utility layers often compile to larger scripts than necessary.

**Before:**
```aiken
mint(redeemer: Action, policy_id: PolicyId, self: Transaction) {
  validate_spending_side_state(self) &&
  check_mint(redeemer, policy_id, self)
}
```

**After:**
```aiken
mint(redeemer: Action, policy_id: PolicyId, self: Transaction) {
  expect [Pair(asset_name, quantity)] =
    self.mint
      |> assets.tokens(policy_id)
      |> dict.to_pairs()

  check_mint(redeemer, asset_name, quantity, self)
}
```

**Profiling note:** This is often a reliable architectural win when the policy only cares about minting conditions.
**Validation note:** Confirm with generated script size and representative benchmarks. A smaller dependency surface is a strong heuristic, not a language guarantee.

---

## OPT-8: Use Reference Scripts When Reuse and Size Justify the Deployment Cost (Applicable from Babbage era and later)

**Why it matters:** Reference scripts let frequently reused scripts live on-chain once, so spending transactions do not need to carry the full script bytes every time.

**Good candidate:**
- Scripts reused across many transactions
- Multi-script transactions close to size limits
- Larger validators where witness size is a recurring pain point

**Tradeoffs:**
- You must publish and maintain the script-bearing UTxO
- That output carries min-ADA and operational overhead
- The break-even depends on transaction frequency and script size

**Guideline:** Treat reference scripts as an architectural optimization. They are often valuable, but there is no universal threshold that makes them automatically correct.

---

## OPT-9: Use Inline Datums When Witness Savings Outweigh Output Bloat (Applicable from Babbage era and later)

**Why it matters:** Inline datums move datum bytes into the output, which can reduce witness payload on spend transactions.

**Good candidate:**
- Data is read repeatedly from the same UTxO
- Spending transactions are witness-size constrained
- The datum is naturally part of the UTxO's long-lived state

**Tradeoffs:**
- Larger outputs
- Higher min-ADA on datum-carrying UTxOs
- Potentially more state bloat if large datums are stored inline

**Guideline:** Inline datums often help stateful protocols, but the break-even depends on datum size and spend frequency.

---

## OPT-10: Keep Canonical State Compact

**Why it matters:** Large canonical state makes future spends slower, larger, and harder to maintain.

**Common win:**
- Store hashes or compact summaries on-chain instead of large payloads
- Keep frequently checked fields near the top-level state representation
- Avoid making every spend walk large user-controlled collections

**Profiling note:** This is usually an architectural win rather than a micro-optimization.

---

## OPT-11: Measure with Representative Transactions, Not Toy Inputs

**Why it matters:** The same validator can look cheap on tiny tests and expensive once you add realistic values, multiple inputs, or large datums.

**What to measure:**
- Script size
- CPU / memory on the heaviest realistic paths
- Effect of multiple simultaneous script inputs
- Effect of realistic datum, queue, and value sizes

**Testing guidance:**
- Use `test` for targeted examples
- Use property tests with fuzzers for invariants
- Use `bench` for cost growth with increasing input complexity

---

## OPT-12: Treat Toolchain and Version Advice as Version-Sensitive

**Why it matters:** Aiken compiles to Plutus ledger languages, and optimization behavior depends on compiler, stdlib, and ledger version.

**When to call this out:**
- V2 vs V3 deployment targets
- Changes in stdlib helpers or transaction shape
- Advice involving reference inputs, inline datums, or reference scripts
- Advice involving traces, benchmarks, or generated script size

**Guideline:** Confirm the project's Aiken version, stdlib version, and target ledger version before turning an optimization idea into a recommendation.

---

## OPT-13: Keep `Value` / `dict` Work Narrow and Reused

**Why it matters:** Repeated `assets.tokens`, `assets.quantity_of`, `dict.to_pairs`, or broad `Value` traversals can become a hidden hot path, especially when attacker-controlled values can grow.

**Before:**
```aiken
let minted_pairs =
  self.mint
    |> assets.tokens(policy_id)
    |> dict.to_pairs()

let target_qty =
  assets.quantity_of(self.mint, policy_id, expected_asset_name)

let burn_qty =
  assets.quantity_of(self.mint, policy_id, burn_asset_name)
```

**After:**
```aiken
let own_tokens = assets.tokens(self.mint, policy_id)

// Idiomatic approach: explicit when-branch, works across all stdlib versions.
let target_qty =
  when dict.get(own_tokens, expected_asset_name) is {
    Some(q) -> q
    None    -> 0
  }

let burn_qty =
  when dict.get(own_tokens, burn_asset_name) is {
    Some(q) -> q
    None    -> 0
  }
```

**Note on `dict.get_or_else` (stdlib v3.0.0+):**
If your stdlib version provides `dict.get_or_else`, verify its exact signature before use.
Unlike `option.or_else`, the official `dict.get_or_else` helper takes a thunk fallback
`fn() -> value`, not a direct default value — so the call form may be:
```aiken
// Only if your stdlib version confirms this signature:
let target_qty = dict.get_or_else(own_tokens, expected_asset_name, fn() { 0 })
```
When in doubt, prefer the explicit `when dict.get(...) is` form above, which is unambiguous
and works across all versions.

**Guideline:** Slice `Value` down to the policy or asset family you actually need, then reuse that narrowed `Dict` or value fragment instead of re-traversing the full `Value` repeatedly. Prefer documented stdlib lookups over project-invented helper names when giving generic advice.

**Profiling note:** This is still a benchmark question. It matters most when values can contain many assets or when the same branch queries the same policy repeatedly.

---

## Common Budget Diagnoses

Use this table as "what to inspect next", not as a deterministic root-cause map.

| Symptom | Common things to check next | Typical directions |
|---|---|---|
| Budget grows sharply with more inputs | repeated traversals, repeated decoding, per-input duplicated logic | OPT-2, OPT-3, OPT-4 |
| Large datum makes spends expensive | eager decoding, oversized canonical state, repeated semantic checks | OPT-6, OPT-9, OPT-10 |
| Multi-script transaction fails near size limits | repeated witnesses, large validators, no reference scripts | OPT-7, OPT-8 |
| Test costs look fine but production is tight | unrealistic tests, traces present, tiny inputs only | OPT-1, OPT-5, OPT-11 |
| Advice depends on version quirks | unclear toolchain target | OPT-12 |
