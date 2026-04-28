# Aiken Security Patterns Reference

Use these patterns after reconstructing contract intent (Step 3, SA-9).
Patterns confirm and name invariant gaps — they do not discover new ones.

A missing check is not automatically a bug. For every pattern:
- Confirm the contract actually relies on that invariant
- Distinguish a confirmed exploit from a contextual risk
- Prefer `N/A` when the pattern is intentionally irrelevant

Classification discipline:
- `❗ Confirmed vulnerability`: the shown code permits a concrete attacker-constructible exploit
- `⚠️ Contextual risk`: likely dangerous, but impact depends on missing context or off-chain assumptions
- `💡 Best-practice improvement`: safer pattern, but current code may still be correct

Evidence discipline:
- Treat Aiken / stdlib / ledger API statements as factual claims that require official documentation or visible project code
- **Pattern severity labels (CRITICAL / HIGH / MEDIUM) are default review priors, not immutable verdicts.**
  Final finding severity must be assigned by independent judgment against actual exploit impact.
  Availability-only issues often deserve lower severity than the pattern default.
  Never copy a pattern label directly to a finding without re-evaluating against the specific code.

False-positive guardrails:
- Do not flag missing `else` handlers when unsupported purposes are intentionally rejected
- Do not treat `expect` itself as a vulnerability; it is idiomatic fail-fast validation in Aiken
- Do not treat `expect typed: MyDatum = data` as semantic validation of business rules
- Do not require signatory checks for permissionless actions
- Do not require single-input constraints for intentionally batched flows
- Do not require time windows for timeless semantics
- Do not require exact global transaction balancing on-chain; the ledger already balances the transaction
- Do not flag arbitrary junk UTxOs at a script address as protocol state when the protocol already authenticates canonical state with a token, reference, or unique identity
- Do not flag a hashed-datum design as a vulnerability merely because inline datums were not used;
  only flag missing semantic validation of datum content

Code snippets below are illustrative. Adapt them to the project's actual Aiken version, stdlib version, and helper functions.
If a helper name is not obviously from your codebase or referenced stdlib modules, treat it as schematic rather than guaranteed API surface.

Handler-surface reminder:
- `spend`: bind checks to `own_ref`, the current input, and any required successor outputs / datums
- `mint`: bind checks to `policy_id` and the exact asset names and quantities minted or burned under that policy
- `withdraw`: bind checks to `account`, the intended stake credential, and the exact reward / withdrawal semantics
- `publish`: bind checks to the certificate index in `tx.certificates` and the certificate type and content
- `vote`: bind checks to the Voter type and credential (received as `voter: Voter`); find the matching Voter entry in `tx.votes` (`Pairs<Voter, Pairs<GovernanceActionId, Vote>>`, sorted in ascending order) and validate GovernanceActionId and Vote content — `Vote(Voter)` in ScriptPurpose carries no `at` position index (unlike `Publish` and `Propose`); the review focus is Voter, GovernanceActionId, and Vote content binding
- `propose`: bind checks to the proposal procedure index in `tx.proposal_procedures` and the proposal payload content

Pattern dependencies to remember:
- Pattern 6 often partially mitigates Pattern 1, but single-input constraints alone are not enough without unique output or identity binding
- **Pattern 3 and Pattern 10 should usually be checked together and share a root cause**: successor datum presence is not the same as successor datum semantic validity. If both apply to the same datum gap, report one finding.
- **Pattern 9 and Pattern 17 share a root cause when both apply to the same reference input**: authenticating a reference input matters only if the protocol also identifies which state is canonical. If both apply, report one finding.
- **Pattern 3 + Pattern 10 + Pattern 18 can all trace to one datum-handling gap**: when they do, consolidate into one finding with all three pattern names listed.
- Pattern 19 introduces cross-script trust assumptions; always check Pattern 5 (authorization) and Pattern 9 (canonical state identity) alongside it.

Quick triage:
- `spend`: start with `own_ref`, current-input identity, successor outputs / datums, and value continuity. Common first checks: Patterns 1, 3, 4, 6, 8, 9, 10, 13, 16, 20, 21.
- `mint`: start with `policy_id`, exact asset names, exact quantities, and authorization. Common first checks: Patterns 2, 4, 11, 12, 13, 20.
- `withdraw`: start with `account`, reward semantics, authorization, and any trusted reference state. Common first checks: Patterns 4, 5, 7, 9, 11, 13, 17, 19.
- `publish` / `propose`: start with `at` index binding, authority, payload content, and canonical referenced state. Common first checks: Patterns 5, 7, 9, 11, 13, 17. (V3/Conway only)
- `vote`: start with Voter identity and credential, GovernanceActionId and Vote content binding in `tx.votes`, authority, and any trusted reference state. Common first checks: Patterns 5, 7, 9, 11, 13, 17. (V3/Conway only)
- Forwarding / delegating validators: always check Pattern 19 alongside Pattern 5.
- Multi-redeemer validators: always check Pattern 20 across all redeemer paths.
- Address outputs to beneficiaries or protocol addresses: check Pattern 21.
- Review order: identify the active handler and action path, reconstruct protocol-specific invariants, then match only the relevant patterns below.
- **V2 note**: For Plutus V2 (pre-Conway) projects, governance patterns (`publish` / `vote` / `propose`) do not apply. All handler signatures use `fn(datum, redeemer, ctx) -> Bool` with `ScriptContext`; adapt pattern code examples accordingly.

---

## Pattern 1: Double Satisfaction (CRITICAL)

**Problem:** Two script inputs both accept the same output as "payment", so an attacker unlocks multiple UTxOs while only satisfying one obligation.

**When to flag:**
- The validator accepts "there exists an output paying X"
- Multiple relevant script inputs can be co-spent
- The output is not uniquely bound to the current input or state

**Common false positives:**
- Single-input protocols that provably never co-spend relevant UTxOs
- Protocols that already bind outputs by nonce, input reference, or state token

**Vulnerable pattern:**
```aiken
spend(datum: Option<Datum>, redeemer: Redeemer, own_ref: OutputReference, self: Transaction) {
  list.any(self.outputs, fn(output) {
    output.address == payment_address &&
    assets.lovelace_of(output.value) >= expected_lovelace
  })
}
```

**Fix:**
```aiken
pub type Datum {
  payment_nonce: ByteArray,
}

spend(datum_opt: Option<Datum>, redeemer: Redeemer, own_ref: OutputReference, self: Transaction) {
  expect Some(datum) = datum_opt

  list.any(self.outputs, fn(output) {
    output.address == payment_address &&
    assets.lovelace_of(output.value) >= expected_lovelace &&
    // `output_payment_nonce` is a project-specific helper that extracts the
    // nonce from the output datum — adapt to your actual datum structure.
    output_payment_nonce(output) == datum.payment_nonce
  })
}
```

**Better design:** Bind each spend to a unique identity such as the input `OutputReference`, a tagged output, or a state-thread token.

---

## Pattern 2: Negative Integer Bypass (HIGH)

**Problem:** Logic assumes numbers are positive, but Aiken `Int` values can be negative.

**When to flag:**
- Datum or redeemer integers influence payouts, counters, deltas, or mint / burn quantities
- The code checks upper bounds but not lower bounds

**Common false positives:**
- Signed quantities are intentionally allowed and handled correctly
- Values are validated into a non-negative domain before use

**Vulnerable pattern:**
```aiken
spend(datum_opt: Option<State>, redeemer: Action, own_ref: OutputReference, self: Transaction) {
  expect Some(datum) = datum_opt

  when redeemer is {
    Withdraw(amount) -> amount <= datum.locked_lovelace
    _ -> False
  }
}
```

**Fix:**
```aiken
spend(datum_opt: Option<State>, redeemer: Action, own_ref: OutputReference, self: Transaction) {
  expect Some(datum) = datum_opt

  when redeemer is {
    Withdraw(amount) -> {
      // 1. Validate the redeemer value itself
      amount > 0 &&
      amount <= datum.locked_lovelace &&

      // 2. Validate that value actually flows correctly (see also Pattern 4).
      // Without this, an attacker can pass Withdraw(1) but take all funds.
      // `find_own_input` and `find_successor` are project helpers — adapt to
      // your actual codebase.
      expect Some(own_input) =
        list.find(self.inputs, fn(i) { i.output_reference == own_ref })
      let own_lovelace = assets.lovelace_of(own_input.output.value)
      expect Some(successor) = find_successor(self, own_ref)
      let successor_lovelace = assets.lovelace_of(successor.value)
      expect Some(user_output) =
        list.find(self.outputs, fn(o) { o.address == datum.beneficiary })
      let paid = assets.lovelace_of(user_output.value)

      paid == amount &&
      successor_lovelace == own_lovelace - amount
    }

    _ -> False
  }
}
```

**Note:** This fix addresses both the negative-integer bypass and the value-flow verification
(Pattern 4). Apply lower-bound checks only to fields that the protocol defines as non-negative.
For signed domains such as mint / burn quantities or explicit deltas, validate the allowed sign
and magnitude instead of forcing a universal `> 0` rule.

---

## Pattern 3: Unconstrained Successor Datum (CRITICAL)

**Problem:** A continuing output is required, but the validator does not validate the datum attached to that successor output.

**When to flag:**
- The contract rolls state forward
- Future behavior depends on the successor datum

**Common false positives:**
- Terminal paths that intentionally produce no successor
- Protocols where the next state is authenticated elsewhere and datum contents are irrelevant

**Vulnerable pattern:**
```aiken
// `continuing_outputs` is a project helper — see note below on successor identification.
expect [next_output] = continuing_outputs(self, own_ref)
next_output.value == expected_value
```

`continuing_outputs(self, own_ref)` is shown as a representative project helper name for locating successor outputs tied to the current input. In concrete code, verify the actual helper surface for your Aiken version and project; official building blocks include `transaction.find_input`, `transaction.resolve_input`, `transaction.find_script_outputs`, and `transaction.find_datum`.

**`find_script_outputs` is not sufficient alone**: `transaction.find_script_outputs` returns *all* outputs paying to a script hash — not the outputs specifically continuing the current input. Without additional identity binding (e.g., a tag derived from `own_ref`, a state-thread token, or a nonce in the datum), using it bare as a successor finder reintroduces double satisfaction and state confusion. Always bind successor identification to a unique identity; then use `find_script_outputs` as a filter if needed, not as the sole locator.

**Fix:**
```aiken
fn resolve_output_datum(output: Output, tx: Transaction) -> Option<Data> {
  when output.datum is {
    InlineDatum(raw) -> Some(raw)
    DatumHash(hash) ->
      // `transaction.find_datum` is the generic stdlib helper here.
      // In a DatumHash branch, a direct lookup over `tx.datums` can also be correct when
      // the project's stdlib models datum witnesses as a Dict, but the exact surface is
      // version-sensitive. Adapt this lookup to the confirmed project helpers when needed.
      transaction.find_datum([output], tx.datums, hash)
    NoDatum -> None
  }
}

expect Some(current_state) = datum_opt

expect [next_output] = continuing_outputs(self, own_ref)
expect Some(raw_next) = resolve_output_datum(next_output, self)
expect next_state: State = raw_next

next_output.value == expected_value &&
valid_transition(current_state, next_state, redeemer)
```

**Better design:** Validate value and successor datum together so state and asset flow cannot diverge. Only require inline datums here if the protocol truly depends on inline-datum semantics; otherwise accept either inline or hashed datum and validate the decoded content.

**Pattern dependency:** Pattern 3 and Pattern 10 often share the same root cause (missing or unvalidated successor datum content). If both apply, report one finding with both pattern names.

---

## Pattern 4: Weak Value Accounting / Protocol Value Relation Failure (CRITICAL)

**Problem:** The script fails to enforce the exact asset relation the protocol relies on.

The ledger already guarantees global transaction balance. The bug is that the validator does not prove the protocol-specific relation it actually cares about: exact payout, exact remaining locked value, exact minted quantity, or exact asset continuity.

**When to flag:**
- A spend path pays value out of the script
- A successor output should preserve remaining funds
- A mint / burn path must match business rules exactly
- Specific assets must stay locked, move to a known recipient, or remain unchanged

**Common false positives:**
- Do not flag merely because the contract does not prove `total_in == total_out`
- Do not assume fees must be modeled on-chain unless the protocol accounting depends on them
- Do not require one universal equality for protocols that intentionally split or merge state

**Address comparison note:** When checking that value is paid to the correct recipient
(`output.address == beneficiary`), confirm the required granularity:
- Full address equality (payment + stake credentials) — use when the protocol requires a specific wallet + staking configuration
- Payment credential equality only — use when the protocol means "any output controlled by this payment key, regardless of staking"
Incorrect granularity is a semantic and security error, not merely style.

**Vulnerable pattern:**
```aiken
list.any(self.outputs, fn(output) {
  output.address == beneficiary &&
  assets.lovelace_of(output.value) >= requested_lovelace
})
```

**Fix — enforce the exact relation the protocol depends on:**
```aiken
fn valid_simple_withdraw(
  own_lovelace: Int,
  successor_lovelace: Int,
  paid_to_user: Int,
  amount: Int,
) -> Bool {
  paid_to_user == amount &&
  own_lovelace == successor_lovelace + amount
}
```

**Better design:** Express accounting in exact assets and exact parties, not generic "at least" conditions.

---

## Pattern 5: Missing Signatory or Capability Validation (HIGH)

**Problem:** A privileged path does not verify that the authorized party or capability approved the transaction.

**When to flag:**
- Admin actions
- Emergency actions
- Parameter changes
- Owner-only withdrawals or closes
- Certificate or governance actions with privileged effects

**Common false positives:**
- Permissionless actions
- Protocols that authorize via state token, governance state, or another on-chain capability

**Vulnerable pattern:**
```aiken
when redeemer is {
  AdminAction(new_params) -> update_params(new_params)
  _ -> False
}
```

**Fix:**
```aiken
when redeemer is {
  AdminAction(new_params) ->
    list.has(self.extra_signatories, admin_key_hash) &&
    update_params(new_params)

  _ -> False
}
```

**Better design:** For upgradeable systems, authorize via capability token or governance state instead of hard-coding one key forever.

---

## Pattern 6: Improper Input Constraints (CRITICAL)

**Problem:** The validator does not constrain how many relevant inputs may participate, enabling state merges or double-satisfaction variants.

**When to flag:**
- The logic assumes a single relevant script input
- Output matching is shared across multiple inputs
- State transitions are only valid one-at-a-time

**Common false positives:**
- Protocols intentionally designed for batching or many-input aggregation
- Protocols that correctly bind each input to a unique successor

**Fix — only when single-input semantics are required:**
```aiken
// `is_relevant_input` is a project-specific predicate — e.g., checks script
// address, state token presence, or datum type. Adapt to your actual code.
let relevant_inputs =
  list.filter(self.inputs, fn(input) { is_relevant_input(input) })

list.length(relevant_inputs) == 1 &&
validate_transition(...)
```

**Better design:** If multiple inputs are intentional, compute over the exact participating set rather than pretending the transaction is single-input.

---

## Pattern 7: Overly Broad or Missing Validity Window (HIGH)

**Problem:** The contract has time-sensitive semantics, but the on-chain validity range is absent or broader than intended.

**When to flag:**
- Vesting, auctions, liquidations, timeouts, expiries, claim windows
- Oracle or quote freshness requirements
- Any logic where "when the transaction executes" changes what should be allowed

**Common false positives:**
- Timeless validators whose semantics do not depend on time
- Protocols where freshness is enforced by another reviewed invariant

**Vulnerable pattern:**
```aiken
spend(datum, redeemer, own_ref, self) {
  validate_business_logic(datum, redeemer, self)
}
```

**Fix:**
```aiken
let range = self.validity_range

// Pseudocode: replace with explicit checks from your stdlib version's
// `interval` helpers or your project's equivalent window-validation logic.
within_expected_window &&
validate_business_logic(datum, redeemer, self)
```

**Better design:** When reference inputs or external quotes are involved, pair time-window checks with explicit freshness checks on the referenced state.

---

## Pattern 8: Brittle Validation Path / Overuse of Attacker-Dependent `expect` (MEDIUM)

**Problem:** The validator uses `expect`, `list.at`, or other shape assumptions on attacker-controlled data in a way that either hides a missing cardinality constraint or collapses an alternate valid branch into immediate rejection.

`expect` is idiomatic in Aiken. The risk is not "using `expect`". The risk is using it where the contract should instead validate shape explicitly and either:
- enforce exact cardinality as part of the protocol invariant, or
- branch intentionally when `None` or another alternate shape is still semantically valid

**When to flag:**
- `expect` on lists or outputs whose cardinality is not already enforced
- `expect Some(x) = ...` where `None` should lead to an alternate valid path rather than immediate rejection
- Helper functions that hide attacker-dependent shape assumptions

**Common false positives:**
- Mandatory boundary assertions where any mismatch should reject
- Local `expect` that is provably safe because an earlier check enforced the same shape

**Related patterns:**
- If the real issue is "there must be exactly one relevant input / output", also review Pattern 6
- If the real issue is "the optional branch changes protocol semantics", review the action-specific invariants before calling it a vulnerability

**Vulnerable pattern:**
```aiken
expect Some(next_output) = list.at(continuing_outputs(self, own_ref), 0)
```

**Fix:**
```aiken
when continuing_outputs(self, own_ref) is {
  [next_output] -> validate_output(next_output)
  _ -> False
}
```

**Better design:** Keep attacker-influenced shape checks explicit near the point of use.

---

## Pattern 9: Missing Canonical State / UTxO Identity Check (CRITICAL)

**Problem:** The contract treats "some UTxO at this address" or "some well-formed reference input" as authoritative state.

**When to flag:**
- Singleton state machines
- Config, oracle, or governance reference inputs
- Logic that assumes one specific state UTxO is authoritative

**Common false positives:**
- Simple validators that only reason about the currently spent input
- Cases where identity is already bound by state token, fixed `OutputReference`, or another reviewed invariant

**Fix — bind authority to a unique identity:**
```aiken
expect Some(own_input) =
  list.find(self.inputs, fn(input) { input.output_reference == own_ref })

assets.quantity_of(own_input.output.value, state_policy_id, state_asset_name) == 1
```

**Fix — for trusted reference inputs, validate identity explicitly:**
```aiken
// `expected_config_ref` is a protocol constant, parameter, or immutable state link.
expect Some(config_input) =
  list.find(
    self.reference_inputs,
    fn(input) { input.output_reference == expected_config_ref },
  )
```

**Better design:** Preserve the same identity across transitions, for example with a state-thread token.

**Pattern dependency:** Pattern 9 and Pattern 17 often share a root cause when both apply to the same reference input. If so, report one finding with both pattern names.

---

## Pattern 10: Weak Datum Validation / Semantic Data Acceptance (HIGH)

**Problem:** The validator accepts any datum that decodes to the expected Aiken type, even if the value is semantically invalid for the protocol.

Typed `expect` proves "well-formed". It does not prove "allowed state".

**When to flag:**
- Datum fields drive balances, owners, phases, deadlines, counters, policy IDs, or capabilities
- Successor datums or reference datums influence permissions or accounting

**Common false positives:**
- Datum fields that are informational only
- Cases where stronger transition checks already imply the same invariant

**Vulnerable pattern:**
```aiken
expect Some(raw_state) = datum_opt
expect state: State = raw_state
state.phase == Active
```

**Fix** (uses `resolve_output_datum` from Pattern 3):
```aiken
// `valid_state`, `valid_owner`, `valid_phase` are project-specific semantic
// validators — adapt to your actual datum fields and business rules.
fn valid_state(state: State) -> Bool {
  state.balance >= 0 &&
  valid_owner(state.owner) &&
  valid_phase(state.phase)
}

expect Some(previous_state) = datum_opt
// `continuing_outputs` is a project helper — see Pattern 3 note on successor identification.
expect [next_output] = continuing_outputs(self, own_ref)
expect Some(raw_next) = resolve_output_datum(next_output, self)
expect next_state: State = raw_next

valid_state(next_state) &&
valid_transition(previous_state, next_state, redeemer)
```

**Better design:** Keep datum schemas small and intentional. Re-check critical semantic fields even when they already have a type. If the protocol specifically requires inline datums for interoperability or witness-size reasons, state that requirement explicitly instead of assuming it.

**Pattern dependency:** Pattern 10 and Pattern 3 often share the same root cause. If both apply to the same missing datum validation gap, report one finding.

---

## Pattern 11: Redeemer Validation Failure (HIGH)

**Problem:** The handler accepts unexpected redeemer variants or leaves action-specific invariants under-specified.

**When to flag:**
- Wildcard cases
- Default-`True` branches
- Missing action-specific checks

**Vulnerable pattern:**
```aiken
when redeemer is {
  Deposit(amount) -> validate_deposit(amount)
  Withdraw(amount) -> validate_withdraw(amount)
  _ -> True
}
```

**Fix:**
```aiken
when redeemer is {
  Deposit(amount) -> validate_deposit(amount)
  Withdraw(amount) -> validate_withdraw(amount)
  Close -> validate_close(...)
}
```

**Better design:** Make each redeemer constructor map to one explicit state transition with dedicated invariants.
During review, enumerate every constructor first; do not let one explicit branch hide weaker or missing checks on the others.

---

## Pattern 12: Token Name / Minting Quantity Attack (HIGH)

**Problem:** A minting policy checks that something was minted under the policy, but not the exact asset names or quantities.

**When to flag:**
- NFTs
- One-shot minting
- Policies with exact-quantity semantics

**Common false positives:**
- Policies intentionally supporting many asset names or variable quantities

**Vulnerable pattern:**
```aiken
// Checking for non-empty is not sufficient — it does not verify the exact asset name
// or quantity. An attacker can mint any token name under the policy and pass this check.
!dict.is_empty(assets.tokens(self.mint, policy_id))
```

**Fix:**
```aiken
expect [Pair(asset_name, quantity)] =
  self.mint
    |> assets.tokens(policy_id)
    |> dict.to_pairs()

asset_name == expected_asset_name &&
quantity == expected_quantity
```

**Better design:** Validate token name, quantity, and authorization together.

---

## Pattern 13: Unbounded Data / Value / Traversal DoS (HIGH)

**Problem:** A user-controlled datum, value map, or queue can grow until future validations become too expensive or operationally impractical.

**When to flag:**
- Deposit or enqueue paths can append unbounded state
- Future spends must deserialize or iterate over user-controlled collections
- The protocol treats many same-address UTxOs as active work items

**Common false positives:**
- Protocols that authenticate one canonical state UTxO and ignore unrelated outputs
- Designs where large off-chain data is committed by hash and not re-walked on-chain

**Fix:**
```aiken
// Project-specific invariant helpers shown schematically.
bounded_queue_length(next_state) <= max_queue_len &&
bounded_payload(next_state)
```

**Better design:** Keep large data off-chain, keep on-chain state compact, and bound the size of any collection the validator must traverse.

---

## Pattern 14: Availability / UTxO Contention / Throughput Bottleneck (MEDIUM)

**Problem:** Too much protocol traffic depends on one hot UTxO, so legitimate transactions contend with each other and the protocol may suffer degraded availability or throughput.

This is usually an availability / UX risk, not a direct theft primitive by itself.

**When to flag:**
- One global state UTxO gates many users
- Throughput matters to the protocol

**Common false positives:**
- Admin-only or low-throughput systems where contention is acceptable

**Design pattern — sharding or partitioning:**
```aiken
// Placeholder project function, not a stdlib guarantee.
fn shard_index(user: VerificationKeyHash, shard_count: Int) -> Int {
  ...
}
```

**Better design:** Partition load across independent state UTxOs and reconcile in controlled merge steps. Escalate severity only when the throughput bottleneck meaningfully breaks protocol liveness or creates a downstream safety failure.

---

## Pattern 15: Cheap Spam / Protocol-Recognized Griefing (MEDIUM)

**Problem:** An attacker can cheaply create many candidate outputs that the protocol may mistake for valid requests, or can bloat maintenance work by forcing scans over low-value items.

Anyone can send funds to a script address. A validator cannot prevent arbitrary outputs from being created there. The real question is whether the protocol mistakenly treats those outputs as recognized state or recognized requests.

**When to flag:**
- The protocol scans arbitrary same-address UTxOs as live requests
- Public request creation does not require a distinguishing capability
- Future maintenance cost depends on processing all matching outputs

**Common false positives:**
- Protocols that only recognize outputs carrying a request token, state token, or canonical reference

**Fix — authenticate which outputs count as protocol work:**
```aiken
fn is_protocol_request(output: Output) -> Bool {
  assets.quantity_of(output.value, request_policy_id, request_asset_name) == 1
}
```

**Better design:** Use capability tokens, canonical queue UTxOs, bounded queue depth, and only then add a non-trivial ADA commitment as economic friction on validated request-creation paths.

---

## Pattern 16: Locked Value / Bricking (CRITICAL)

**Problem:** A valid transition can move funds into a state that no future transaction can spend.

**When to flag:**
- Complex state machines
- No tested close / recover path
- Transition rules can produce dead states
- **Datum-hash data availability**: outputs locked with `DatumHash` where the datum witness
  has not been published on-chain or stored durably off-chain. If the datum corresponding to
  the hash is lost, the UTxO becomes permanently unspendable — the spender cannot construct
  a transaction that provides the required datum witness. This has caused real fund loss on
  Cardano mainnet.

**Mitigation checklist:**
- Every redeemer path should have at least one reachable successful transaction
- Every live state should have a valid successor or terminal exit
- Recovery / emergency paths should remain valid under partial failure
- Tests should cover state reachability, not only single happy paths
- **Datum-hash recoverability**: if the protocol produces `DatumHash` outputs, require a
  documented recoverability strategy — for example:
  (a) the datum is included in the transaction witness set so it is recorded on-chain, or
  (b) the off-chain infrastructure durably stores datum values and the recovery path is
  documented, or (c) another mechanism ensures the datum can always be reconstructed.
  Inline datums are one valid mitigation, not the default recommendation — do not flag a
  hashed-datum design as a vulnerability merely because inline datums were not used.

**Better design:**
```aiken
when redeemer is {
  EmergencyClose ->
    list.has(self.extra_signatories, admin_key_hash)

  _ ->
    validate_normal_path(...)
}
```

---

## Pattern 17: Reference Input Hijacking (Applicable from Babbage era and later) (HIGH)

**Problem:** The validator trusts a reference input for config, oracle, or metadata without authenticating which UTxO it came from.

**When to flag:**
- Contracts using `reference_inputs`
- Price feeds, config UTxOs, governance state, allowlists

**Common false positives:**
- Reference inputs whose identity is already authenticated by fixed `OutputReference` or trusted token

**Fix:**
```aiken
expect Some(reference_input) =
  list.find(
    self.reference_inputs,
    fn(input) { input.output_reference == expected_reference },
  )
```

**Better design:** Authenticate both identity and freshness of referenced data.

**Pattern dependency:** Pattern 17 and Pattern 9 often share a root cause when both apply to the same reference input. If so, report one finding with both pattern names.

---

## Pattern 18: Missing Datum Semantic Validation (Applicable from Babbage era and later) (HIGH)

**Problem:** The contract reads from an output's datum — inline or hashed — without verifying that the datum satisfies semantic constraints. Structural decoding success is treated as semantic correctness.

This is distinct from Pattern 3 (unconstrained *successor* datum) in that Pattern 18 applies to **any** datum read, including reference inputs and config UTxOs. The root cause is the same: relying on type decoding as a proxy for protocol validity.

**When to flag:**
- Datum fields are read and used to authorize actions, compute amounts, or control state
- Only structural decoding is performed (`expect typed: T = raw`) with no semantic check
- Successor output or reference input datum content is used directly without validation

**Common false positives:**
- Contracts that validate datum content thoroughly after decoding
- Datums that are informational only and do not influence authorization or accounting
- Hashed-datum designs are **not** a vulnerability merely because inline datums were not used

**Do NOT use this pattern to require inline datums** where the protocol is agnostic to datum form.
The appropriate fix is always semantic validation of datum *content*, not a forced switch to inline datums.

**Vulnerable pattern:**
```aiken
// Only checks structural decode — any fee_bps or admin value passes
expect InlineDatum(raw) = output.datum
expect config: Config = raw
use_config(config)
```

**Fix — validate presence and semantic content, regardless of datum form**
(uses `resolve_output_datum` from Pattern 3):
```aiken
// `valid_config` and `valid_admin` are project-specific semantic validators —
// adapt to your actual config fields and business rules.
fn valid_config(config: Config) -> Bool {
  config.fee_bps >= 0 &&
  config.fee_bps <= 10000 &&
  valid_admin(config.admin)
}

expect Some(raw) = resolve_output_datum(output, self)
expect config: Config = raw
valid_config(config)
```

**Better design:** Keep datum schemas small. Validate critical semantic fields explicitly even when they already have a type. Only require `InlineDatum` if the protocol has a specific, documented reason — for instance, off-chain tooling that requires inline-datum semantics for interoperability.

**Pattern dependency:** Pattern 18 often overlaps with Pattern 3 and Pattern 10. If all three trace to one datum-handling gap, report one finding with all three pattern names.

---

## Pattern 19: Forwarding Validation / Withdrawal-Based Cross-Purpose Delegation (HIGH)

**Problem:** A script delegates its authorization logic to another validator via a withdrawal trigger (forwarding validation), but the delegation binding, the withdrawal credential, or the cross-purpose assumption is not correctly enforced.

This is an official Cardano design pattern documented in Aiken Common Design Patterns as
"Forwarding Validation" and related withdrawal tricks. It is widely used in production but
introduces security requirements that do not exist in single-script flows.

**Pattern variants:**
- A `spend` or `mint` handler that authorizes by checking "a specific withdrawal occurred" (forwards validation to a `withdraw` script)
- A `withdraw` handler that acts as a global authorizer for multiple spend or mint scripts
- 0-lovelace withdrawals used as invocation triggers for cross-script coordination

**When to flag:**
- A `spend` / `mint` validator's primary authorization is delegated to a `withdraw` handler
- The forwarding check verifies "any withdrawal exists" rather than "the specific authorized credential withdrew"
- Multiple scripts assume a shared withdrawal validator ran without each independently verifying the credential
- A 0-lovelace withdrawal is used as a trigger but the stake credential is not verified
- The cross-script dependency is undocumented, making the spend/mint script insecure in transactions that omit the withdrawal

**Common false positives:**
- Forwarding designs where the withdrawal validator performs complete semantic validation and
  the spend validator's forwarding check intentionally binds to the correct credential
- Cross-purpose delegation that is correctly documented and verifiable

**Vulnerable pattern:**
```aiken
// Spend validator that forwards authorization — but checks "any withdrawal exists"
// rather than "the specific authorized credential withdrew".
// Note: `withdrawals` is `Pairs<Credential, Lovelace>`, not a Dict.
spend(datum_opt, redeemer, own_ref, self) {
  !list.is_empty(self.withdrawals)
}
```

**Fix — bind to the specific authorized withdrawal credential:**
```aiken
// `withdrawals` is `Pairs<Credential, Lovelace>`.
// Use `pairs.has_key` from `aiken/collection/pairs` for credential presence checks.
use aiken/collection/pairs

spend(datum_opt, redeemer, own_ref, self) {
  let expected_credential = Script(authorized_withdrawal_script_hash)
  pairs.has_key(self.withdrawals, expected_credential)
}
```

**Amount note**: `pairs.has_key` only proves that the credential is present in `self.withdrawals`.
It does not validate the withdrawal amount. If the protocol depends on the amount — for example,
verifying a 0-lovelace withdrawal trigger, or checking that the exact reward amount was claimed —
use `pairs.get_first` or equivalent to also validate the `Lovelace` value alongside the credential.

**Better design:**
- The forwarding spend / mint validator must check the *specific* withdrawal credential, not merely "some withdrawal occurred"
- The withdrawal validator must perform complete semantic validation; it is the security anchor of the entire design
- Document the cross-script dependency explicitly — any script that delegates to a withdrawal validator is insecure if that validator is omitted from the transaction
- If using 0-lovelace withdrawals as invocation triggers, verify the credential and document the off-chain requirement to include the withdrawal in every transaction that must be authorized
- Check Pattern 5 (authorization) and Pattern 9 (canonical state identity) alongside this pattern when the withdrawal validator reads reference state

---

## Pattern 20: Other Redeemer Bypass (CRITICAL)

**Problem:** A validator has multiple redeemer paths within the *same handler*, and the security
of the intended path depends on the attacker actually choosing that path. An attacker submits
the UTxO with an unexpected redeemer that skips the intended checks entirely.

This is distinct from Pattern 11 (Redeemer Validation Failure), which covers missing checks
*within* a redeemer branch. Pattern 20 covers the case where the attacker avoids the intended
branch altogether by using a different redeemer of the same handler.

**Boundary with Pattern 19 (Forwarding Validation):** Cross-handler trust assumptions — e.g.,
a withdraw handler assuming the spend handler already verified state, or a mint policy delegating
authority to a spending validator — are covered by Pattern 19. Pattern 20 is scoped to
same-handler multi-redeemer bypass: the attacker exploits a weaker redeemer branch within
the same spend, mint, or withdraw handler.

**When to flag:**
- The handler has multiple redeemer branches and at least one branch enforces weaker invariants
  than another branch that protects the same assets or state
- The validator has a "maintenance", "batch", or "admin" redeemer with fewer constraints that
  can be used in place of the intended redeemer to drain or manipulate the same UTxO
- A permissive fallback or catch-all branch exists that does not re-enforce the invariants
  of the stricter branches

**Common false positives:**
- Each redeemer path independently enforces all required invariants for its own semantics
- The validator uses a single redeemer type with no permissive fallback

**Vulnerable pattern:**
```aiken
type Action {
  Trade { price: Int }
  Cancel
  Maintenance  // intended for admin cleanup only
}

spend(datum_opt: Option<Order>, redeemer: Action, own_ref: OutputReference, self: Transaction) {
  expect Some(datum) = datum_opt
  when redeemer is {
    Trade { price } ->
      price >= datum.min_price &&
      // ... full trade validation ...
      list.has(self.extra_signatories, datum.buyer)
    Cancel ->
      list.has(self.extra_signatories, datum.owner)
    Maintenance ->
      // Weak: only checks admin sig, does not re-check trade invariants.
      // Attacker can use Maintenance redeemer to drain the UTxO with admin cooperation
      // or if admin key is compromised.
      list.has(self.extra_signatories, admin_key)
  }
}
```

**Fix — each redeemer path must independently enforce its own invariants:**
```aiken
spend(datum_opt: Option<Order>, redeemer: Action, own_ref: OutputReference, self: Transaction) {
  expect Some(datum) = datum_opt
  when redeemer is {
    Trade { price } ->
      price >= datum.min_price &&
      validate_trade(datum, price, self)
    Cancel ->
      list.has(self.extra_signatories, datum.owner) &&
      validate_cancel_returns_value(datum, self)
    Maintenance ->
      list.has(self.extra_signatories, admin_key) &&
      // Maintenance must also enforce that value is preserved or returned,
      // not just that admin signed.
      validate_maintenance_preserves_value(datum, own_ref, self)
  }
}
```

**Better design:** Treat every redeemer path within a handler as independently attackable.
Never rely on "the user will use the right redeemer" — an attacker will use whichever redeemer
has the weakest constraints. Each branch must independently enforce all invariants required
for the assets or state it can touch. For cross-handler trust assumptions (e.g., a spend
handler relying on a withdrawal validator), see Pattern 19 (Forwarding Validation).

---

## Pattern 21: Staking Credential Hijacking (HIGH)

**Problem:** The validator checks the payment credential of an output but ignores the staking
credential, allowing an attacker to redirect staking rewards to an unauthorized address.

Cardano addresses contain both a payment credential and an optional staking credential.
A validator that only verifies the payment portion can lock outputs to addresses whose staking
rewards flow to an attacker-controlled stake key.

**When to flag:**
- Outputs paying to beneficiaries, treasuries, or protocol-controlled addresses
- Address comparisons using only payment credential equality
- Protocols where staking rewards are economically significant
- Successor outputs that should preserve the original staking configuration

**Common false positives:**
- Protocols that intentionally allow any staking credential (e.g., user-facing payments where
  the user controls staking)
- Outputs to script addresses where staking is irrelevant to the protocol
- Protocols that explicitly document staking credential agnosticism

**Vulnerable pattern:**
```aiken
// Only checks payment credential — attacker can substitute their own staking credential
fn pays_to_beneficiary(output: Output, beneficiary_pkh: VerificationKeyHash) -> Bool {
  when output.address.payment_credential is {
    VerificationKey(hash) -> hash == beneficiary_pkh
    _ -> False
  }
  // output.address.stake_credential is never checked — attacker sets it to their own
}
```

**Fix — verify full address when staking matters:**
```aiken
fn pays_to_beneficiary(output: Output, expected_address: Address) -> Bool {
  output.address == expected_address
}
```

**Fix — when only payment credential matters, document the decision:**
```aiken
// Protocol intentionally allows any staking credential for user-facing payments.
// Document this decision in the protocol spec.
fn pays_to_payment_key(output: Output, beneficiary_pkh: VerificationKeyHash) -> Bool {
  when output.address.payment_credential is {
    VerificationKey(hash) -> hash == beneficiary_pkh
    _ -> False
  }
}
```

**Better design:** Default to full address equality. Only relax to payment-credential-only
comparison when the protocol has an explicit, documented reason. When the validator creates
successor outputs at its own script address, verify that the staking credential is preserved
or intentionally set.

---

## Sources

These patterns are grounded in the following official references. Verify API surface and behavior
against the specific Aiken and stdlib version in your project — both can change between releases.

- Aiken Language Tour — Validators (parameters, handler signatures): https://aiken-lang.org/language-tour/validators
- Aiken Language Tour — Modules (`env` module system, `--env` flag): https://aiken-lang.org/language-tour/modules
- Aiken Common Design Patterns (Forwarding Validation, Withdrawal Tricks): https://aiken-lang.org/fundamentals/common-design-patterns
- Aiken Getting Started (`aiken.toml`, `plutus.json`): https://aiken-lang.org/fundamentals/getting-started
- Aiken stdlib `cardano/script_context` (`ScriptInfo`, `Vote(Voter)`, `Publish { at }`, `Propose { at }`): https://aiken-lang.github.io/stdlib/cardano/script_context.html
- Aiken stdlib `cardano/transaction` (`find_input`, `find_script_outputs`, `find_datum`, `withdrawals: Pairs<Credential, Lovelace>`, `votes: Pairs<Voter, ...>`): https://aiken-lang.github.io/stdlib/cardano/transaction.html
- Aiken stdlib `cardano/governance` (`Voter`, `Vote`, `GovernanceActionId`): https://aiken-lang.github.io/stdlib/cardano/governance.html
- Aiken stdlib `cardano/assets`: https://aiken-lang.github.io/stdlib/cardano/assets.html
- Aiken stdlib `aiken/collection/pairs` (`pairs.has_key`, `pairs.get_first`, etc.): https://aiken-lang.github.io/stdlib/aiken/collection/pairs.html
- Aiken Glossary (`config`, `plutus.json`, `bench`, `ScriptContext`): https://aiken-lang.org/glossary
- Plutonomicon — Common Plutus Vulnerabilities (Other Redeemer, UTxO Value Size Spam, etc.): https://plutonomicon.github.io/plutonomicon/vulnerabilities
- MLabs — Plutus Script Vulnerability Guide (Insufficient Staking Control, Other Redeemer): https://library.mlabs.city/common-plutus-security-vulnerabilities
- Cardano Developer Portal — Smart Contract Security Overview: https://developers.cardano.org/docs/build/smart-contracts/advanced/security/overview/
