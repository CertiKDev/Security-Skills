# Plutus Security Patterns Reference

Use these patterns after reconstructing contract intent.

A missing check is not automatically a bug. For every pattern:
- Confirm the contract actually relies on that invariant
- Distinguish a confirmed exploit from a contextual risk
- Prefer `N/A` when the pattern is intentionally irrelevant

In **development security guidance mode**, these patterns serve as an implementation checklist: identify which ones apply to the architecture being built and guide the developer to implement protection proactively, before the code is complete.

Classification discipline (review modes):
- `❗ Confirmed vulnerability`: the shown code permits a concrete attacker-constructible exploit
- `⚠️ Contextual risk`: likely dangerous, but impact depends on missing context or off-chain assumptions
- `💡 Best-practice improvement`: safer pattern, but current code may still be correct

False-positive guardrails:
- Do not require signatory checks for permissionless actions
- Do not require single-script-input constraints for protocols that intentionally aggregate inputs
- Do not require time windows for timeless semantics
- Do not require exact global transaction balancing on-chain; the ledger already balances the transaction
- Do not treat typed decoding as semantic validation
- Do not treat arbitrary same-address UTxOs as protocol state if canonical state is already authenticated elsewhere

Key pattern interactions (check these together):
- P6 partially mitigates P1: single-input constraints reduce double-satisfaction surface, but P1's output binding fix is still needed for full protection.
- P9 is a prerequisite for P17: if canonical state identity (P9) is unprotected, authenticating a reference input (P17) may still be insufficient.
- P3 and P10 must both hold: ensuring a successor output exists (P3) does not validate its semantic contents (P10). Check both together on stateful paths.
- P12 and P19 address different failure modes for minting policies: P12 catches name/quantity gaps when a policy runs, P19 catches the case where the policy can run more than once at all.
- P4 and P22 must be considered together: any exact value-relation check (P4) must account for min-ADA requirements (P22) on continuing outputs.
- P24 affects every pattern that compares `Value`: P1 output matching, P4 accounting, P12 minted-value checks.

Code snippets below are illustrative. Adapt them to the project's actual Plutus version, API layer, and helper functions.

**Helper function note:** Helper functions referenced in patterns (`outputDatumNonce`, `decodeOutputDatum`, `validateDatumTransition`, `checkAuthorization`, etc.) are intentionally not defined here. They represent decode and access helpers that vary by Plutus API layer, library version, and project convention. Implement or verify them in context before using any pattern's fix code. Where a helper's signature matters for security, the pattern notes it explicitly.

---

## Pattern 1: Double Satisfaction (CRITICAL)

**Problem:** Two validators both accept the same output as "payment", so an attacker unlocks multiple UTxOs while only satisfying one economic obligation.

**When to flag:**
- The validator accepts "there exists an output paying X"
- Multiple script inputs can be spent together
- The payment output is not uniquely bound to the current input

**Common false positives:**
- Single-input protocols that provably never co-spend multiple relevant UTxOs
- Protocols that already bind outputs by nonce, state token, or exact input/output pairing

**Exploit path:**
1. Two script UTxOs each expect a 10 ADA payment to the same destination
2. Attacker spends both in one transaction
3. The transaction contains one 10 ADA output satisfying both validators
4. Both validations succeed, but only one economic obligation was actually met

**Vulnerable pattern:**
```haskell
validator datum redeemer ctx =
  let outputs = txInfoOutputs (scriptContextTxInfo ctx)
  in any (\o -> txOutAddress o == paymentAddr && txOutValue o >= expectedAda) outputs
```

**Fix:**
```haskell
data Datum = Datum
  { paymentNonce :: BuiltinByteString
  , ...
  }

validator datum redeemer ctx =
  let info = scriptContextTxInfo ctx
      outputs = txInfoOutputs info
  in any (\o ->
       txOutAddress o == paymentAddr &&
       txOutValue o >= expectedAda &&
       outputDatumNonce o == paymentNonce datum
         -- outputDatumNonce: project-specific helper that extracts the nonce field
         -- from the output's inline datum or datum hash witness
     ) outputs
```

**Better design:** Bind state with a State Thread NFT or another unique identity that must appear in the correct successor output.

---

## Pattern 2: Negative Integer Bypass (HIGH)

**Problem:** Logic assumes numbers are positive, but `Integer` in PlutusTx can be negative.

**When to flag:**
- Redeemer or datum integers influence payouts, balance deltas, counters, or mint amounts
- The code checks upper bounds but not lower bounds

**Common false positives:**
- Values already encoded in a non-negative domain and revalidated before use
- Signed quantities that are intentionally allowed and handled correctly

**Exploit path:**
1. Validator checks `withdrawAmount <= lockedAmount`
2. Attacker passes `withdrawAmount = -1`
3. The bound check passes
4. Downstream accounting or state transition becomes invalid

**Vulnerable pattern:**
```haskell
validator (Datum { lockedAda }) (Redeemer { withdrawAda }) ctx =
  traceIfFalse "too much" (withdrawAda <= lockedAda)
```

**Fix:**
```haskell
validator (Datum { lockedAda }) (Redeemer { withdrawAda }) ctx =
  traceIfFalse "amount must be positive" (withdrawAda > 0) &&
  traceIfFalse "too much" (withdrawAda <= lockedAda)
```

**Note:** Apply non-negativity checks to deltas, counters, and quantity-like fields, not only to direct payout amounts.

---

## Pattern 3: Unconstrained Output Datum (CRITICAL)

**Problem:** A continuing output is required, but the validator does not validate the datum attached to that output.

**When to flag:**
- The contract rolls state forward
- Future behavior depends on the continuing output datum

**Common false positives:**
- Transactions that intentionally terminate the contract and produce no continuing output
- Protocols where the next state is authenticated elsewhere and datum contents are irrelevant

**Exploit path:**
1. Attacker spends a live state UTxO
2. The validator checks the continuing output value but not its datum
3. The attacker writes a malicious but spendable next-state datum
4. Funds remain locked under attacker-chosen state

**Vulnerable pattern:**
```haskell
validator datum redeemer ctx =
  let [contOut] = getContinuingOutputs ctx
  in txOutValue contOut == expectedValue
```

**Fix:**
```haskell
validator datum redeemer ctx =
  case getContinuingOutputs ctx of
    [contOut] ->
      let newDatum = decodeOutputDatum contOut
          -- decodeOutputDatum: project-specific helper that reads and decodes
          -- the inline datum or datum hash witness from a TxOut
      in txOutValue contOut == expectedValue &&
         validateDatumTransition datum newDatum redeemer
    _ -> traceError "expected exactly one continuing output"
```

**Better design:** Validate value and datum together so state and asset flow cannot diverge.

---

## Pattern 4: Weak Value Accounting / Protocol Value Relation Failure (CRITICAL)

**Problem:** The validator fails to enforce the protocol-specific asset relation it relies on.

The ledger already guarantees that the full transaction balances. The bug is that the script does not prove the value relation the protocol actually cares about: exact payout, exact remaining script value, exact minted amount, or exact asset continuity.

**When to flag:**
- A spend path pays value out of the script
- A continuing output should preserve remaining funds
- A minting or burning action must match business rules exactly
- Specific assets must stay locked, move to a known recipient, or remain unchanged

**Common false positives:**
- Do not flag merely because the validator does not prove `totalIn == totalOut`
- Do not assume fees must be modeled on-chain unless the contract's own accounting depends on them
- Do not require one universal equality for protocols that intentionally split or merge state across multiple UTxOs

**Exploit path:**
1. The script input contains protocol-controlled value
2. The validator only checks one favorable condition, such as "user got at least X"
3. The attacker reshapes the remaining outputs or token mix in a way the protocol did not allow
4. The transaction still balances globally, but the protocol loses funds or corrupts state

**Vulnerable pattern:**
```haskell
validator datum redeemer ctx =
  let info = scriptContextTxInfo ctx
  in txOutValue (head $ filter toUser $ txInfoOutputs info) >= withdrawValue
```

**Fix — enforce the protocol's exact value relation:**
```haskell
-- Example: simple one-input, one-successor withdraw flow
validator datum (Withdraw amt) ctx =
  let info = scriptContextTxInfo ctx
      ownInput = case findOwnInput ctx of
        Just i  -> txInInfoResolved i
        Nothing -> traceError "missing own input"
      ownValue = txOutValue ownInput
      contValue = case getContinuingOutputs ctx of
        [o] -> txOutValue o
        _   -> traceError "expected one continuing output"
      paidToUser = valuePaidTo info beneficiaryPkh
      expectedPaid = Ada.lovelaceValueOf amt
  in traceIfFalse "wrong user payout" (paidToUser == expectedPaid) &&
     traceIfFalse "wrong remaining script value" (ownValue == contValue <> expectedPaid)
```

**Interaction with P22:** The equality `ownValue == contValue <> expectedPaid` may need to account for min-ADA requirements on the continuing output. See P22 for details.

**Better design:** Express accounting in terms of exact assets and exact parties, not generic "at least" conditions. If multiple script inputs/outputs are intentional, sum exactly the participating values rather than relying on global transaction balance.

---

## Pattern 5: Missing Signatory Validation (HIGH)

**Problem:** A privileged action does not verify that the authorized party approved the transaction.

**When to flag:**
- Admin actions
- Emergency actions
- Parameter changes
- Owner-only withdrawals or closes

**Common false positives:**
- Permissionless actions
- Protocols that authorize by NFT or another on-chain capability instead of a PKH

**Exploit path:**
1. Contract exposes an admin-only redeemer path
2. Validator does not require the correct signer or capability
3. Any user can execute the privileged action

**Vulnerable pattern:**
```haskell
validator datum (AdminAction newParams) ctx = updateParams newParams
```

**Fix:**
```haskell
validator datum (AdminAction newParams) ctx =
  traceIfFalse "not signed by admin" (txSignedBy info adminPkh) &&
  updateParams newParams
  where
    info = scriptContextTxInfo ctx
    -- IMPORTANT: adminPkh must come from a trusted, attacker-uncontrollable source:
    -- a script parameter fixed at compile time, a canonical state token datum,
    -- or an on-chain governance record. If adminPkh is read from the redeemer
    -- or an unauthenticated datum, this check provides no protection.
```

**Better design:** For upgradeable or decentralized systems, authorize by capability token or governance state instead of hard-coding a single PKH forever.

---

## Pattern 6: Improper Input Constraints (CRITICAL)

**Problem:** The validator does not constrain how many relevant inputs may participate, enabling unexpected state merges or double-satisfaction variants.

**When to flag:**
- The logic assumes a single relevant script input
- The output matching logic is shared across multiple inputs
- State transitions are only valid one-at-a-time

**Common false positives:**
- Batch processors or protocols intentionally designed for many-input aggregation
- Protocols that correctly bind each input to a unique successor

**Exploit path:**
1. Attacker spends multiple relevant script inputs together
2. The validator reasons locally about each input
3. Shared outputs satisfy multiple checks or state is merged unexpectedly

**Fix — when single-input semantics are required:**
```haskell
validator datum redeemer ctx =
  let info           = scriptContextTxInfo ctx
      relevantInputs = filter isRelevantInput (txInfoInputs info)
  in case relevantInputs of
       [singleInput] -> validateTransition singleInput
       _             -> traceError "expected exactly one relevant input"
```

**Note on P6 vs OPT-11:** The pattern-match form above is preferred over `length relevantInputs == 1` for two reasons: (1) it is compatible with the single-pass style recommended in OPT-11; (2) it binds the input in the same expression, avoiding a second traversal. Use `length` only when you need to count but intentionally do not process the element in the same branch.

**Better design:** If multiple inputs are required, bind each one to a unique identity or compute over the exact set of participating state UTxOs.

---

## Pattern 7: Overly Broad or Missing Validity Window (HIGH)

**Problem:** The contract has time-sensitive semantics, but the on-chain validity range is absent or broader than the protocol intends.

**When to flag:**
- Vesting, auctions, liquidations, timeouts, expiries, claim windows
- Oracle or quote freshness requirements
- Any logic where "when the transaction executes" changes what should be allowed

**Common false positives:**
- Timeless validators whose semantics do not depend on time
- Contracts where freshness is enforced by another reviewed on-chain invariant

**Exploit path:**
1. Off-chain code assumes the action will happen during a narrow window
2. The validator allows a much broader or unbounded validity interval
3. The attacker waits until external conditions change, then submits the still-valid transaction
4. The contract accepts an action outside its intended execution window

**Vulnerable pattern:**
```haskell
validator datum redeemer ctx =
  -- uses deadline in comments or off-chain code, but no on-chain range check
  validateBusinessLogic datum redeemer ctx
```

**Fix — constrain the validity range as tightly as the semantics require:**
```haskell
validator datum redeemer ctx =
  let info  = scriptContextTxInfo ctx
      range = txInfoValidRange info
  in traceIfFalse "outside allowed window"
       (contains (interval start end) range) &&
     validateBusinessLogic datum redeemer ctx
  -- IMPORTANT: start and end must come from a trusted, attacker-uncontrollable source:
  -- a script parameter, the canonical datum authenticated by a state token,
  -- or an on-chain governance record. If read from the redeemer or an
  -- unauthenticated input, the window constraint provides no protection.
```

**Better design:** If reference inputs or external quotes are involved, pair the validity window with explicit freshness checks on the referenced state.

---

## Pattern 8: Partial Function / Brittle Validation Path (MEDIUM)

**Problem:** Partial functions or incomplete pattern matches make the validator fail on unexpected but constructible transaction shapes.

The risk is usually denial of service or brittle spend paths. It becomes a permanent bricking issue only if every reachable recovery path can hit the same failure.

**When to flag:**
- `head`, `tail`, `!!`, `fromJust`
- Incomplete matches on redeemer, datum shape, `Maybe`, or transaction lists
- Helper functions that hide partiality

**Common false positives:**
- A local partial-looking pattern that is provably total because the same branch already enforced exact shape
- Off-chain-only helper code that never runs on-chain

**Exploit path:**
1. Attacker or routine user constructs a transaction with an unexpected list length or missing field
2. The validator evaluates a partial function
3. Validation fails before the intended invariant is checked
4. Legitimate transactions may be blocked; in the worst case, recovery paths are lost

**Vulnerable pattern:**
```haskell
let contOut = head (getContinuingOutputs ctx)
```

**Fix:**
```haskell
case getContinuingOutputs ctx of
  [o] -> validateOutput o
  _   -> traceError "expected exactly one continuing output"
```

**Better design:** Convert all attacker-influenced list and `Maybe` handling into explicit shape checks close to the point of use.

---

## Pattern 9: Missing Canonical State / UTxO Identity Check (CRITICAL)

**Problem:** The contract treats "some UTxO at this script address" or "some reference input with the right shape" as authoritative state.

`findOwnInput` identifies the currently validated input. It does not, by itself, prove that the input or reference UTxO is the canonical state/config/oracle UTxO that the protocol intended to trust.

**When to flag:**
- Singleton state machines
- Contracts that coordinate across multiple UTxOs
- Protocols that read config, oracle, or governance UTxOs
- Logic that assumes one specific state UTxO is authoritative

**Common false positives:**
- Simple validators that only reason about their own spent input and do not depend on global state identity
- Cases where identity is already bound by state NFT, fixed `TxOutRef`, or another reviewed invariant

**Exploit path:**
1. The protocol expects one authoritative state/config/oracle UTxO
2. The attacker supplies a lookalike UTxO at the same address, or a fake reference input with compatible datum shape
3. The validator accepts that lookalike as trusted state
4. Authorization, pricing, or state-transition checks now operate on attacker-chosen data

**Fix — bind authority to a unique identity:**
```haskell
validator datum redeemer ctx =
  let ownInput = case findOwnInput ctx of
        Just i  -> txInInfoResolved i
        Nothing -> traceError "missing own input"
  in traceIfFalse "missing state NFT"
       (valueOf (txOutValue ownInput) stateNftCurrency stateNftName == 1)
```

**Fix — if a specific reference UTxO is required, validate its identity explicitly:**
```haskell
-- General utility: find a reference input by its exact TxOutRef
getValidatedRefInput :: ScriptContext -> TxOutRef -> TxInInfo
getValidatedRefInput ctx expectedRef =
  case find (\i -> txInInfoOutRef i == expectedRef)
            (txInfoReferenceInputs $ scriptContextTxInfo ctx) of
    Just i  -> i
    Nothing -> traceError "missing trusted reference input"
```

**Better design:** Preserve the same state identity across transitions, for example by carrying the same State Thread NFT from input to successor output.

---

## Pattern 10: Weak Datum Validation / Semantic Datum Acceptance (HIGH)

**Problem:** The validator accepts any datum that decodes to the expected Haskell type, even if the value is semantically invalid for the protocol.

Typed decoding is necessary, but it only proves "well-formed". It does not prove "allowed state".

**When to flag:**
- Datum fields drive balances, owners, phases, deadlines, counters, policy IDs, or capabilities
- Continuing output datums or reference datums influence permissions or accounting

**Common false positives:**
- Datum fields that are informational only and do not affect validation
- Cases where stronger transition checks already imply the same invariant

**Exploit path:**
1. The attacker constructs a datum that matches the Haskell type
2. The datum violates business rules or represents an impossible state
3. The validator decodes it successfully and checks only a narrow subset of fields
4. The protocol enters an invalid or attacker-favorable state

**Vulnerable pattern:**
```haskell
-- unsafeFromBuiltinData only proves the data is well-formed for the type.
-- It does NOT validate that the decoded value satisfies business invariants.
validator rawDatum rawRedeemer rawCtx =
  let datum    = unsafeFromBuiltinData rawDatum    :: MyDatum
      redeemer = unsafeFromBuiltinData rawRedeemer :: MyRedeemer
      ctx      = unsafeFromBuiltinData rawCtx      :: ScriptContext
  in actualValidator datum redeemer ctx
  -- Bug: actualValidator may never check that datum fields are in valid ranges
```

**Fix — decode, then validate state invariants and transition invariants:**
```haskell
validateDatum :: MyDatum -> Bool
validateDatum d =
  balance d >= 0 &&
  validOwnerField d &&
  validPhase d

validator datum redeemer ctx =
  case getContinuingOutputs ctx of
    [successorOut] ->
      let newDatum = decodeOutputDatum successorOut
          -- decodeOutputDatum: project-specific helper; see helper note at top
      in traceIfFalse "invalid next datum" (validateDatum newDatum) &&
         traceIfFalse "invalid transition" (validTransition datum newDatum redeemer)
    _ -> traceError "expected exactly one continuing output"
```

**Better design:** Keep datum schemas small and intentional. Re-validate critical semantic fields even when they already have a Haskell type.

---

## Pattern 11: Redeemer Validation Failure (HIGH)

**Problem:** The validator accepts unexpected redeemer variants or leaves behavior under-specified.

**When to flag:**
- Wildcard cases
- Default-`True` branches
- Unhandled action-specific invariants

**Common false positives:**
- Validators with an explicitly exhaustive redeemer ADT that has no wildcard branch and where every constructor is handled with dedicated invariants

**Exploit path:**
1. The contract exposes a wildcard or default-`True` redeemer branch
2. Attacker submits an unexpected or future redeemer variant
3. The branch accepts without performing the intended invariant checks
4. Funds are unlocked or state is changed without satisfying the protocol's required conditions

**Vulnerable pattern:**
```haskell
case redeemer of
  Deposit amt  -> validateDeposit amt
  Withdraw amt -> validateWithdrawal amt
  _            -> True
```

**Fix:**
```haskell
case redeemer of
  Deposit amt  -> validateDeposit amt
  Withdraw amt -> validateWithdrawal amt
  Close        -> validateClose
```

**Better design:** Make each redeemer constructor correspond to one explicit state transition with dedicated invariants.

---

## Pattern 12: Token Name / Minting Policy Attack (HIGH)

**Problem:** The minting policy checks that something was minted under the policy, but not the exact token names, quantities, and authorization.

**When to flag:**
- NFTs
- One-shot minting
- Policies with exact-quantity semantics

**Common false positives:**
- Policies intentionally supporting many token names or variable quantities

**Exploit path:**
1. Policy checks only that minted value under `ownCurrencySymbol` is positive
2. Attacker mints expected tokens plus extra unintended tokens
3. Policy succeeds, but token supply rules are broken

**Fix:**
```haskell
policy redeemer ctx =
  let info      = scriptContextTxInfo ctx
      minted    = txInfoMint info
      ownCS     = ownCurrencySymbol ctx
      ownTokens = map (\(_, tn, qty) -> (tn, qty))
                    (filter (\(cs, _, _) -> cs == ownCS) (flattenValue minted))
                    -- flattenValue: from plutus-ledger-api (e.g. Plutus.V2.Ledger.Api or
                    -- PlutusLedgerApi.V2). Confirm the import path for your plutus-ledger-api
                    -- version. In projects using the cardano-api layer, the equivalent
                    -- decomposition may differ.
  in case ownTokens of
       [(tn, qty)] ->
         tn == expectedTokenName &&
         qty == expectedQuantity &&
         checkAuthorization redeemer info
         -- checkAuthorization: verify minting is permitted by the correct signer,
         -- capability token, or protocol state — not just that the right amount was minted
       _ -> traceError "unexpected tokens minted"
```

**Better design:** Validate token name, quantity, and authorization together. None of the three alone is sufficient.

---

## Pattern 13: Unbounded Input / Value / Datum DoS (HIGH)

**Problem:** User-controlled state, values, or queues can grow until future validations become too expensive or operationally impractical.

**When to flag:**
- Deposit paths accept arbitrary large datum payloads
- Value maps can grow without bounds
- Future spends must deserialize or iterate over attacker-supplied data
- The protocol treats many same-address UTxOs as active work items

**Common false positives:**
- Protocols that authenticate one canonical state UTxO and ignore unrelated outputs
- Designs where large off-chain data is committed by hash and not re-walked on-chain

**Fix:**
```haskell
validator datum redeemer ctx =
  let datumSize = lengthOfByteString (serialiseData (toBuiltinData datum))
      -- serialiseData: PlutusTx.Builtins.serialiseData, available from plutus-tx >= 1.1
      -- (Plutus V1 era). Confirm presence in your plutus-tx version before relying on it.
  in traceIfFalse "datum too large for this protocol" (datumSize <= maxDatumBytes) &&
     traceIfFalse "queue too deep" (queueLength datum <= maxQueueLen) &&
     validateBusinessLogic datum redeemer ctx
```

**Note:** `maxDatumBytes` and `maxQueueLen` here are protocol-defined bounds, not universal ledger constants.

**Better design:** Keep large data off-chain, keep canonical on-chain state compact, and bound any collection that future validators must traverse.

---

## Pattern 14: UTxO Contention / Throughput Bottleneck (MEDIUM)

**Problem:** Too much protocol traffic depends on one hot UTxO, so legitimate transactions contend with each other.

**When to flag:**
- One global state UTxO gates many users
- Throughput matters to the protocol

**Common false positives:**
- Admin-only contracts or low-throughput systems where contention is acceptable

**Design pattern — sharding:**
```haskell
-- Route a user to one of n independent state shards based on their pubkey hash.
-- Each shard is a separate UTxO; transactions touch only the relevant shard.
-- Reconciliation of aggregated state happens off-chain or in controlled merge steps.
shardIndex :: PubKeyHash -> Integer -> Integer
shardIndex pkh n =
  let bytes     = getPubKeyHash pkh
      firstByte = indexByteString bytes 0
  in firstByte `modInteger` n
```

**Better design:** Partition load across independent state UTxOs indexed by shard. Bound the number of shards to keep merge logic tractable. Never let a single UTxO become a prerequisite for all users.

---

## Pattern 15: Cheap Spam / Protocol-Recognized Griefing Attack (MEDIUM)

**Problem:** An attacker can cheaply create many outputs that the protocol may mistake for valid requests, or can bloat maintenance work by forcing scans over low-value items.

A spending validator cannot prevent arbitrary outputs from being created at its address. The real question is whether the protocol mistakenly treats those outputs as recognized state or recognized requests.

**When to flag:**
- The protocol scans arbitrary same-address UTxOs as live requests
- Public request creation does not require a distinguishing capability
- Future maintenance cost depends on processing all matching outputs

**Common false positives:**
- Closed systems where only trusted actors can create protocol UTxOs
- Protocols that only recognize outputs carrying a request token, state token, or canonical identity

**Exploit path:**
1. The protocol scans or processes all outputs at the script address as valid work items
2. Attacker creates many cheap UTxOs at that address without any capability token
3. Future transactions must process or skip all of them, increasing ExUnits cost
4. Legitimate users cannot complete transactions within budget, or off-chain operators face unsustainable scan and maintenance costs

**Mitigation:**
```haskell
isProtocolRequest :: TxOut -> Bool
isProtocolRequest o =
  valueOf (txOutValue o) requestPolicyId requestTokenName == 1
```

**Better design:** Authenticate which outputs count as protocol work with capability tokens, canonical queue UTxOs, and bounded queue depth. Use minimum deposits only as additional economic friction on validated request-creation paths.

---

## Pattern 16: Locked Value / Bricking (CRITICAL)

**Problem:** A valid transition can move funds into a state that no future transaction can spend.

**When to flag:**
- Complex state machines
- No tested close / recover path
- Transition rules can produce "dead" states

**Common false positives:**
- Contracts with provably exhaustive recovery paths and tested close logic
- Timelocked contracts where every reachable state has a valid terminal transition

**Exploit path:**
1. A state transition produces a datum or value configuration that no redeemer can successfully consume
2. Funds are permanently trapped — either by a design flaw or by intentional griefing with a malformed successor datum
3. No emergency path exists, or the emergency path itself requires a state that can no longer be reached

**Vulnerable pattern:**
```haskell
-- Close is defined in the ADT but never handled, so no transaction shape
-- can ever successfully spend a UTxO that reaches the Closed datum state.
data Redeemer = Deposit | Withdraw | Close

validator datum redeemer ctx =
  case redeemer of
    Deposit  -> validateDeposit datum redeemer ctx
    Withdraw -> validateWithdraw datum redeemer ctx
    Close    -> True  -- no invariants: always succeeds but funds may still be unspendable
                      -- if the datum or value shape produced by Withdraw has no valid exit
```

**Mitigation checklist:**
- Every redeemer path should have a reachable successful transaction
- Every live datum state should have at least one valid successor or terminal exit
- Recovery / emergency paths should remain valid even under partial failure

**Better design:**
```haskell
data Redeemer = Deposit | Withdraw | EmergencyClose

validator datum EmergencyClose ctx =
  let info = scriptContextTxInfo ctx
  in txSignedBy info adminPkh
```

**Warning:** The `EmergencyClose` pattern above is illustrative only. An admin-key emergency exit is a single point of failure and a potential backdoor. Before using it, explicitly consider: where are funds sent on emergency close, who controls `adminPkh` and how is that key secured, what governance or timelock constraints should gate the action, and what happens if `adminPkh` is compromised or lost. A bare `txSignedBy info adminPkh` check with no output constraints is not a secure emergency design — it is a key-controlled drain.

---

## Pattern 17: Reference Input Hijacking (V2+) (HIGH)

**Problem:** The validator trusts a reference input for config, oracle, or metadata without authenticating which UTxO it came from.

**When to flag:**
- V2+ contracts using reference inputs
- Price feeds, config UTxOs, governance state, allowlists

**Common false positives:**
- Reference inputs whose identity is already authenticated by NFT or fixed `TxOutRef`

**Exploit path:**
1. Contract reads a value from a reference input
2. Attacker supplies a fake but well-formed reference UTxO
3. Validator consumes attacker-chosen data as trusted config/oracle state

**Fix:**
```haskell
-- Domain-specific helper: find and validate an oracle reference input by identity.
-- Named distinctly from the general getValidatedRefInput utility in P9.
getOracleRefInput :: ScriptContext -> OracleConfig -> TxOut
getOracleRefInput ctx config =
  let refInputs = txInfoReferenceInputs (scriptContextTxInfo ctx)
      oracleInput = find (\i -> txInInfoOutRef i == oracleTxOutRef config) refInputs
  in case oracleInput of
       Just i  -> txInInfoResolved i
       Nothing -> traceError "oracle reference input not found"
```

**Better design:** Authenticate both identity and freshness of reference data. Identity alone (matching a `TxOutRef`) proves which UTxO was used but not that the data is recent. Pair identity checks with a validity window check (P7) or an on-chain timestamp field in the oracle datum to enforce freshness.

---

## Pattern 18: Inline Datum Mismatch (V2+) (HIGH)

**Problem:** The contract expects an inline datum but does not verify that the datum is present, decodes correctly, and matches the intended semantics.

**When to flag:**
- V2+ contracts that rely on inline datums for state or config

**Common false positives:**
- Contracts that intentionally support either inline datum or datum hash and validate both branches correctly

**Fix:**
```haskell
getInlineDatum :: TxOut -> MyDatum
getInlineDatum txOut =
  case txOutDatum txOut of
    OutputDatum d ->
      case fromBuiltinData (getDatum d) of
        Just datum -> datum
        Nothing    -> traceError "datum decode failed"
    _ -> traceError "expected inline datum"

-- After decoding, always apply semantic validation.
-- fromBuiltinData only proves the data is well-formed for the type;
-- it does NOT verify that field values satisfy business invariants.
-- Call validateDatum (see P10) on the decoded result before trusting any field.
```

**Better design:** Validate presence, successful decoding, and semantic constraints together. "Decodes without error" is not equivalent to "contains valid protocol state". Treat the three as separate checks, all of which must pass.

---

## Pattern 19: Missing One-Shot Uniqueness Guarantee (HIGH)

**Problem:** A minting policy is intended to mint exactly one token ever (NFT or state thread token), but does not consume a specific `TxOutRef` to enforce that uniqueness. Without consuming a specific UTxO, the policy can be invoked multiple times across different transactions.

**When to flag:**
- Policies intended to produce globally unique tokens (NFTs, state thread tokens)
- One-shot minting where exactly one token must ever exist under the policy
- Policies that do not burn and re-mint to maintain uniqueness

**Common false positives:**
- Policies intentionally allowing multiple minting transactions (fungible tokens, parametric policies)
- Policies where uniqueness is enforced by an external constraint already reviewed and confirmed

**Exploit path:**
1. The policy checks token name and quantity but not that a specific UTxO is consumed
2. The policy's conditions can be satisfied by constructing a second valid minting transaction
3. Multiple tokens exist under the same currency symbol, breaking the uniqueness invariant
4. Downstream contracts that rely on `valueOf ownCS tokenName == 1` as a unique state token or NFT identity are compromised

**Vulnerable pattern:**
```haskell
-- Policy checks quantity and name but not which UTxO is consumed.
-- Nothing prevents a second identical minting transaction.
policy redeemer ctx =
  let minted = txInfoMint (scriptContextTxInfo ctx)
      ownCS  = ownCurrencySymbol ctx
  in valueOf minted ownCS expectedTokenName == 1
```

**Fix — consume a specific TxOutRef to guarantee one-time execution:**
```haskell
-- The TxOutRef to consume is fixed as a script parameter at deployment time.
-- The ledger rule that any specific UTxO can only be consumed once makes
-- this policy permanently non-repeatable after the seeding transaction.
policy (expectedRef :: TxOutRef) redeemer ctx =
  let info   = scriptContextTxInfo ctx
      inputs = txInfoInputs info
  in traceIfFalse "must consume seeding UTxO"
       (any (\i -> txInInfoOutRef i == expectedRef) inputs) &&
     traceIfFalse "wrong token name or quantity"
       (valueOf (txInfoMint info) (ownCurrencySymbol ctx) expectedTokenName == 1)
```

**Better design:** Pass the seeding `TxOutRef` as a script parameter so the compiled policy hash is unique per deployment instance. The uniqueness guarantee is provided by the ledger, not by on-chain counting logic. Combine with P12 to also enforce authorization and absence of extra tokens under the same policy.

---

## Staking Script Patterns

The following patterns apply to scripts that run in the `Rewarding` and `Certifying` script purposes (Plutus V2+). In Plutus V3, staking scripts also execute for governance-related certificate actions; those cases require additional domain-specific review beyond these patterns.

A staking script does not guard a UTxO. It guards an action on the reward account or the stake credential. The attacker model is different from spending validators: the attacker does not need to construct a UTxO; they only need to submit a transaction that includes the relevant withdrawal or certificate action, triggering the script.

---

## Pattern 20: Unauthorized Reward Withdrawal (staking/rewarding) (HIGH)

**Problem:** The staking script allows reward withdrawals without verifying that the authorized party approved the transaction.

**When to flag:**
- The script runs in the `Rewarding` purpose
- It does not check the transaction signatory or a controlling capability token

**Common false positives:**
- Permissionless withdrawal designs where any party may trigger withdrawal to a fixed address
- Scripts where authorization is enforced by a separate spending validator that must be co-executed in the same transaction

**Exploit path:**
1. The staking script runs on every reward withdrawal for the associated stake credential
2. The script does not require a specific signer or capability
3. Any party can construct a withdrawal transaction for the stake credential's reward account
4. The reward balance is drained to an attacker-chosen address

**Vulnerable pattern:**
```haskell
-- Rewarding script that accepts any withdrawal
stakingValidator redeemer ctx =
  let ScriptContext _ (Rewarding _) = ctx
  in True
```

**Fix:**
```haskell
stakingValidator redeemer ctx =
  let info = scriptContextTxInfo ctx
  in case scriptContextScriptInfo ctx of
       RewardingScript _cred ->
         traceIfFalse "not authorized" (txSignedBy info ownerPkh)
         -- ownerPkh must come from a script parameter or canonical state token,
         -- not from the redeemer (see P5 trust source note)
       _ -> traceError "unexpected script purpose"
```

**Better design:** For multi-party or DAO-controlled stake accounts, authorize withdrawals via an NFT-gated spending validator that must be co-executed in the same transaction, rather than embedding authorization logic in the staking script alone.

---

## Pattern 21: Unauthorized Certificate Action (staking/certifying) (HIGH)

**Problem:** The staking script permits stake credential registration, deregistration, or delegation changes without verifying authorization.

**When to flag:**
- The script runs in the `Certifying` purpose (V1/V2) or handles certificate actions in V3
- It does not distinguish between certificate types or check authorization per action

**Common false positives:**
- Scripts that intentionally allow permissionless re-registration (e.g., protocols that rely on the deposit mechanism)
- Cases where the spending validator for the associated UTxO already enforces the authorization and the staking script co-execution is guaranteed by protocol design

**Exploit path:**
1. The script does not check which certificate action is being performed
2. Attacker submits a transaction with a delegation certificate pointing to an attacker-controlled pool
3. The script accepts because it does not validate the certificate type or target
4. The stake is silently redirected; the protocol's yield or governance weight is compromised

**Vulnerable pattern:**
```haskell
-- Certifying script that accepts any certificate action
stakingValidator redeemer ctx =
  let ScriptContext _ (Certifying _) = ctx
  in txSignedBy (scriptContextTxInfo ctx) ownerPkh
  -- Signs for all certificate types without checking which action is being taken
```

**Fix:**
```haskell
stakingValidator redeemer ctx =
  let info = scriptContextTxInfo ctx
  in case scriptContextScriptInfo ctx of
       CertifyingScript _ix cert ->
         traceIfFalse "not authorized" (txSignedBy info ownerPkh) &&
         traceIfFalse "unexpected certificate type" (isAllowedCert cert)
         -- isAllowedCert: project-specific predicate that restricts which
         -- DCert constructors this script permits (e.g., only DCertDelegDelegate,
         -- not DCertDelegDeRegKey unless a separate close redeemer is provided)
       _ -> traceError "unexpected script purpose"
```

**Better design:** Handle each certificate action explicitly. Deregistration should require the same or stronger authorization as delegation. Pool selection (the target `PoolId`) should be validated against an allowlist or governance state if the protocol has staking-pool constraints.

---

## Cardano-Native Patterns

The following patterns address Cardano-specific mechanics that affect architecture decisions early in development. Unlike P1–P21, these are not about missing validation logic — they are about protocol-level constraints that make otherwise-correct-looking code fail or behave unexpectedly.

---

## Pattern 22: min-ADA Distortion of Value Accounting (MEDIUM)

**Problem:** The Cardano ledger enforces a minimum ADA requirement on every UTxO. When a validator does exact value accounting (P4), the min-ADA constraint can make the intended value equation impossible to satisfy, because the continuing output must carry more lovelace than the "pure" accounting math predicts.

This is not a validation logic bug — it is a protocol-level constraint that must be incorporated into the accounting design from the start.

**When to flag:**
- The validator enforces exact value equality on continuing outputs (e.g., `ownValue == contValue <> expectedPaid`)
- The protocol handles multi-asset values where native token transfers may leave insufficient ADA on the continuing output
- The validator does not explicitly account for min-ADA headroom

**Common false positives:**
- Protocols that only hold ADA (no native tokens) and whose value flows always leave enough ADA naturally
- Protocols where the off-chain builder is explicitly documented and reviewed to pad min-ADA, and the validator's accounting inequality is designed to allow that padding

**Exploit path:**
1. The validator enforces `contValue == ownValue - withdrawnValue`
2. A legitimate withdrawal reduces the lovelace below the continuing output's min-ADA requirement
3. The transaction cannot be submitted because the ledger rejects the output, not the validator
4. Funds are effectively locked — the validator would accept the transaction, but the ledger will not

**Architectural guidance:**
- Decide at design time whether the validator enforces exact equality or an inequality with min-ADA headroom
- If using exact equality, ensure the protocol's value flows can never produce a continuing output below min-ADA
- If using an inequality (`contValue >= expectedMinimum`), ensure the slack does not introduce a value-drain exploit (attacker overpays the continuing output to extract value elsewhere)
- Consider storing a protocol-defined min-ADA floor in the datum or script parameters

**Fix sketch:**
```haskell
-- Instead of exact equality, allow min-ADA headroom while bounding the slack
validator datum (Withdraw amt) ctx =
  let ...
      expectedCont   = ownValue - Ada.lovelaceValueOf amt
      actualCont     = txOutValue contOut
      -- Allow the continuing output to carry UP TO protocolMinAdaBuffer extra lovelace,
      -- but no more. This prevents both min-ADA rejection and value drain.
      adaDifference  = Ada.fromValue actualCont - Ada.fromValue expectedCont
  in traceIfFalse "wrong non-ADA assets in continuing output"
       (nonadaValue actualCont == nonadaValue expectedCont) &&
     traceIfFalse "insufficient continuing value"
       (adaDifference >= 0) &&
     traceIfFalse "excessive ADA padding"
       (adaDifference <= protocolMinAdaBuffer)
```

**Better design:** Define your protocol's value accounting in terms of exact non-ADA asset tracking plus bounded ADA headroom. Never assume that a valid value equation on paper will also satisfy the ledger's min-ADA rule at submission time.

---

## Pattern 23: Script Address Staking Credential Control (MEDIUM)

**Problem:** When a script address is created, it has a payment credential (the script hash) and optionally a staking credential. The staking credential controls who can withdraw ADA staking rewards accumulated at that address and who can delegate the stake. If the protocol does not explicitly choose and control the staking credential, the rewards and delegation authority may be controlled by an unintended party.

This is an address-level architecture decision, not a validation logic bug. It must be made when the script address is first constructed, not retrofitted later.

**When to flag:**
- The protocol holds significant ADA at a script address for extended periods
- No explicit staking credential design is documented or visible in the address construction
- The protocol does not include reward withdrawal or delegation in its threat model

**Common false positives:**
- Protocols that explicitly use a staking credential controlled by the protocol's governance
- Short-lived UTxOs where staking rewards are negligible
- Protocols that intentionally delegate staking control to users or a DAO

**Risk scenario:**
1. The protocol creates a script address with no staking credential, or with a staking credential controlled by the deployer
2. Large amounts of ADA accumulate at the script address over time
3. The staking rewards are silently withdrawn by whoever controls the staking credential
4. The protocol's users do not realize that staking yield on protocol-locked ADA is being captured by a third party

**Architectural guidance:**
- At address construction time, explicitly decide: who should control staking rewards? Who should control delegation?
- If the protocol should control rewards: use a script-based staking credential (P20/P21 apply)
- If users should control rewards: document this explicitly and ensure users understand the model
- If no staking is intended: document why the accumulated rewards are acceptable to forfeit or why they will be negligible

**Better design:** Treat the staking credential as a first-class protocol design parameter. Include it in the architecture documentation and threat model. If rewards are material, use a staking script (protected by P20/P21) as the staking credential so that withdrawal and delegation are both on-chain-authorized.

---

## Pattern 24: Multi-Asset Value Accounting And Comparison Pitfalls (MEDIUM)

**Problem:** Plutus `Value` is a nested map (`Map CurrencySymbol (Map TokenName Integer)`). Value comparison and arithmetic have subtle semantics that differ from intuitive expectations, especially around zero entries and multi-asset ordering.

**When to flag:**
- The validator compares `Value` objects with `==` and both sides may contain different sets of currency symbols or token names
- The validator uses `>=` or `<=` on `Value` (these check component-wise, not total ordering)
- The validator constructs `Value` objects by combining maps from different sources
- The protocol handles multiple distinct native tokens

**Common false positives:**
- Protocols that only handle ADA (single-asset) where `Value` comparison reduces to `Integer` comparison
- Cases where canonical Value construction helpers are already in use and tested

**Key semantics to understand:**
1. **Zero entries**: `Value` maps may or may not contain entries with amount `0`. Two `Value` objects can represent the same economic value but compare as `!=` because one contains explicit zero entries and the other does not. This depends on the Plutus API layer and version in use.

2. **Partial ordering of `>=` / `<=`**: `a >= b` on `Value` means "for every (currencySymbol, tokenName) in b, the amount in a is >= the amount in b". This is a partial order, not a total order. It is possible that neither `a >= b` nor `b >= a` holds. This means `not (a >= b)` does NOT imply `b > a`.

3. **`<>` (mappend) accumulates**: `a <> b` adds amounts per token. It does not union-or-replace. If both sides have the same token, the amounts are summed.

**Vulnerable pattern:**
```haskell
-- Assumes == works correctly across differently-constructed Value objects.
-- May fail if one side has zero entries for tokens the other side omits.
validator datum redeemer ctx =
  let expectedValue = Ada.lovelaceValueOf 10_000_000 <> myTokenValue
      actualValue   = txOutValue contOut
  in actualValue == expectedValue
```

**Architectural guidance:**
- Define canonical Value construction helpers for your protocol that normalize zero entries
- When checking value relations, be explicit about what you are asserting: exact equality of all assets, ADA-only comparison plus separate token checks, or component-wise bounds
- Never use `Value` inequality (`>=`, `<=`) as if it were a total order
- When comparing multi-asset values, consider decomposing into separate ADA and non-ADA checks

**Fix sketch:**
```haskell
-- Decompose value comparison into explicit, unambiguous checks
checkValueRelation :: Value -> Value -> Bool
checkValueRelation actual expected =
  -- Check ADA component exactly
  Ada.fromValue actual == Ada.fromValue expected &&
  -- Check each required token explicitly by currency symbol and token name
  valueOf actual myCS myTN == valueOf expected myCS myTN &&
  -- Ensure no unexpected tokens are present
  length (flattenValue actual) == length (flattenValue expected)
```

**Better design:** Do not rely on generic `Value` equality for protocol accounting. Define protocol-specific value assertions that check exactly the assets and quantities your protocol cares about, and explicitly handle or exclude assets you do not care about. Treat `Value` as a bag of named quantities, not as a single comparable number.
