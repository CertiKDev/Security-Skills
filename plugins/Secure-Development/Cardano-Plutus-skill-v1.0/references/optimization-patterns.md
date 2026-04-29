# Plutus Performance Optimization Reference

Cardano meters script execution with ExUnits and also constrains transaction size, but the exact budgets and break-even points depend on:
- current protocol parameters
- Plutus version
- compiler / plugin version
- transaction composition
- datum and value sizes

Treat this document as a profiling-first reference, not a list of guaranteed wins.

Optimization discipline:
1. Preserve correctness first. Never weaken validation to save ExUnits.
2. Prefer measured claims over stylistic guesses.
3. Distinguish architectural wins from micro-optimizations.
4. Call out version-sensitive advice explicitly.
5. When in doubt, compile and evaluate representative transactions before recommending a change.

**Tooling note:** ExUnits measurements require off-chain tooling (e.g., `cardano-cli transaction build`, the Plutus evaluation API, or a testnet submission). Static code review alone can only generate hypotheses about cost drivers — not confirmed measurements. Label claims accordingly.

---

## OPT-1: Consider `unsafeFromBuiltinData` on Hot Decode Paths

**Why it matters:** `fromBuiltinData` introduces a `Maybe` branch. On validators and policies where decode failure should simply reject the transaction, `unsafeFromBuiltinData` can remove that branch.

**Good candidate:**
- Top-level datum/redeemer/context decoding
- Frequently executed paths where malformed data should always fail hard

**Less compelling candidate:**
- Optional nested fields
- Paths where explicit recovery or clearer error branching matters more than small savings

**Before:**
```haskell
case fromBuiltinData rawDatum of
  Just datum -> validate datum
  Nothing    -> traceError "bad datum"
```

**After:**
```haskell
let datum = unsafeFromBuiltinData rawDatum
in validate datum
```

**Profiling note:** This is often a real win, especially with larger datums or redeemers, but the size of the win depends on the compiled script and toolchain.

**Security note:** `unsafeFromBuiltinData` only proves the data is well-formed for the target Haskell type. It does not validate semantic constraints — field values can still be out of range, in invalid combinations, or represent impossible protocol states. Always apply business-rule validation after decoding. See P10 (Weak Datum Validation) for the distinction between type-level and semantic correctness.

---

## OPT-2: Keep Validation Local to the Fields Each Path Actually Needs

**Why it matters:** Many expensive validators do too much work on every path: scanning outputs, decoding datums, or traversing values even when a branch only needs signatories or minted value.

**Common win:**
- Structure each redeemer path so it touches only the parts of `TxInfo` it needs
- Avoid helper functions that always inspect inputs/outputs when some branches do not need them

**Example:**
```haskell
validator datum redeemer ctx =
  let info = scriptContextTxInfo ctx
  in case redeemer of
       AdminAction   -> txSignedBy info adminPkh
       Withdraw amt  -> checkWithdrawal info datum amt ctx
```

---

## OPT-3: Replace Hot-Path List Closures Only After Profiling

**Why it matters:** Repeated `filter`, `find`, and `map` chains can become expensive in on-chain hot paths, especially when they allocate closures over captured values.

**Before:**
```haskell
-- Note: fromJust is a partial function (see P8). If findOwnInput returns Nothing,
-- this crashes. The optimization target here is the redundant list traversal,
-- not the partiality. The corrected 'after' version uses explicit case matching.
let ownRef   = txInInfoOutRef (fromJust (findOwnInput ctx))
    ownInput = find (\i -> txInInfoOutRef i == ownRef) (txInfoInputs info)
```

**After:**
```haskell
-- Single-pass lookup with explicit failure; no partial function.
findInputByRef :: TxOutRef -> [TxInInfo] -> Maybe TxInInfo
findInputByRef _ [] = Nothing
findInputByRef ref (x:xs)
  | txInInfoOutRef x == ref = Just x
  | otherwise               = findInputByRef ref xs
```

**Profiling note:** This often helps when the same list is traversed frequently or on larger transactions, but not every combinator-heavy function is automatically a problem.

---

## OPT-4: Consider Strict Bindings for Expensive Reused Values

**Why it matters:** If the same expensive expression is consumed in several places, making evaluation more explicit can sometimes reduce duplicated work or make generated code smaller. But this is toolchain-sensitive, not a default rewrite rule.

**Better first step:**
- Check whether the module already opts into `Strict`
- Check whether the compiler / plugin configuration already strictifies bindings
- Only add local bang patterns when compiled-script measurements improve

**Before:**
```haskell
let info = scriptContextTxInfo ctx
in txSignedBy info adminPkh && checkOutputs info
```

**After:**
```haskell
let !info = scriptContextTxInfo ctx
in txSignedBy info adminPkh && checkOutputs info
```

**Profiling note:** This is a heuristic, not a blanket rule. Sometimes the compiled code is already fine because the toolchain already applies strictness-related optimizations. Compare the compiled script and ExUnits before recommending local bang patterns broadly.

---

## OPT-5: Trim Trace Usage in Production Builds

**Why it matters:** Trace strings increase script size, and large numbers of traces can also affect execution cost.

**Development build:**
```haskell
{-# OPTIONS_GHC -fplugin-opt PlutusTx.Plugin:remove-trace=False #-}
validator datum redeemer ctx =
  let info = scriptContextTxInfo ctx
  in traceIfFalse "double satisfaction check" (checkSingleOutput ctx) &&
     traceIfFalse "signatory missing" (txSignedBy info adminPkh)
```

**Production build:**
```haskell
{-# OPTIONS_GHC -fplugin-opt PlutusTx.Plugin:remove-trace=True #-}
```

**Version note:** The `fplugin-opt PlutusTx.Plugin:remove-trace` flag syntax is available in `plutus-tx-plugin` from approximately the Alonzo era onwards, but the exact option name and casing have varied across toolchain releases. Confirm the flag name against the `PlutusTx.Plugin` documentation for the `plutus-tx-plugin` version pinned in your project. Some toolchain configurations expose this via `cabal.project` options rather than per-module pragmas.

**Tradeoff:** Keeping traces improves debugging during development and testnet work. The savings from removing them vary with the number and length of messages.

---

## OPT-6: Prefer Cheaper Data Access Patterns on Hot Datum / Context Paths

**Why it matters:** The main performance risk is usually not ordinary `newtype` wrappers. It is repeated conversion between `BuiltinData`-backed values and native Haskell representations, or decoding large structures when a hot path only needs a few fields.

**Less useful rule:** "Remove every `newtype` wrapper."

**Better rule:** Keep wrappers that improve clarity and safety. If profiling shows that hot paths spend too much time decoding large datums or `ScriptContext`, consider `AsData` / data-backed representations or partial decoding patterns that avoid converting more than the validator actually needs.

**Before:**
```haskell
actualValidator rawDatum rawRedeemer rawCtx =
  let datum    = unsafeFromBuiltinData rawDatum    :: MyDatum
      redeemer = unsafeFromBuiltinData rawRedeemer :: MyRedeemer
      ctx      = unsafeFromBuiltinData rawCtx      :: ScriptContext
  in checkOwner datum && checkCounter datum && checkMint ctx
```

**Alternative when profiling justifies it:**
```haskell
-- Keep large values data-backed on hot paths and decode only the fields you need.
-- The helper names below (decodeDatumAsData, decodeContextAsData, etc.) are
-- project-specific; implement them against the actual API layer in use.
actualValidator rawDatum rawRedeemer rawCtx =
  let datumD = decodeDatumAsData rawDatum
      ctxD   = decodeContextAsData rawCtx
  in checkOwnerField datumD && checkCounterField datumD && checkMintField ctxD
```

**Profiling note:** Treat this as an advanced optimization. Use it only if the codebase can benchmark and maintain the data-backed representation cleanly.

---

## OPT-7: Minimize the On-Chain Dependency Surface of Minting Policies

**Why it matters:** Policies that pull in broad utility layers or unrelated spending-side validation often compile to larger scripts than necessary.

**Bad mental model:** A minting policy should not be modeled like a spending validator with a datum argument. This is not only a performance concern — in Plutus V1/V2, a minting policy takes `(redeemer, ctx)`, not `(datum, ctx)`. The "before" example below represents both a conceptual design error and a type-level interface mismatch.

**Before:**
```haskell
-- This is wrong at two levels:
-- 1. Conceptually: minting policies reason about minting conditions, not datum state.
-- 2. Interface: in Plutus V1/V2, minting policies do not receive a datum argument.
--    This is a type error, not just a performance variation.
policy datum ctx =
  validateDatum datum && checkMinting ctx
```

**After (V1/V2-style):**
```haskell
policy redeemer ctx =
  let info   = scriptContextTxInfo ctx
      minted = txInfoMint info
      ownCS  = ownCurrencySymbol ctx
  in checkTokensUnderPolicy minted ownCS expectedTokenName expectedQty &&
     checkAuthorization redeemer info
```

**Profiling note:** This is usually a reliable architectural win when the policy only cares about minting conditions. Keep datum-heavy validation in the spending validator unless the policy truly needs the same information.

---

## OPT-8: Use Reference Scripts When Reuse and Size Justify the Deployment Cost (V2+)

**Why it matters:** Reference scripts let frequently reused scripts live on-chain once, so spending transactions do not need to carry the full script bytes every time.

**Good candidate:**
- Scripts reused across many transactions
- Multi-script transactions close to size limits
- Larger validators where witness size is a recurring pain point

**Tradeoffs:**
- You must publish and maintain the script-bearing UTxO
- That output carries min-ADA and operational overhead
- The break-even depends on transaction frequency and script size

**Guideline:** Treat reference scripts as an architectural optimization. They are often valuable, but there is no universal size threshold that makes them automatically correct.

---

## OPT-9: Use Inline Datums When Witness Savings Outweigh Output Bloat (V2+)

**Why it matters:** Inline datums move datum bytes into the output, which can reduce witness payload on spend transactions.

**Good candidate:**
- Data is read repeatedly from the same UTxO
- Spending transactions are witness-size constrained
- The datum is naturally part of the UTxO's long-lived state

**Tradeoffs:**
- Larger outputs
- Higher min-ADA on datum-carrying UTxOs
- Potentially more state bloat if large datums are stored inline

**Guideline:** Inline datums often help repeated stateful protocols, but the savings depend on datum size and spend frequency.

---

## OPT-10: Profile Against Representative Transactions Before Recommending Changes

**What to measure:**
- Script size
- ExUnits on the heaviest realistic paths
- Effect of multiple simultaneous script inputs
- Effect of realistic datum and value sizes

**CLI sketch (not a complete recipe):**
```bash
cardano-cli latest transaction build \
  --tx-in <UTXO> \
  --tx-in-script-file validator.plutus \
  --tx-in-datum-file datum.json \
  --tx-in-redeemer-file redeemer.json \
  ...
```

**Important:** The snippet above is a structural sketch only. A complete benchmarking recipe requires: the correct era-specific subcommand for your `cardano-cli` version (`cardano-cli latest` for recent builds; era-prefixed commands for older ones), a funded address and UTXO set on the target network, valid protocol-parameters JSON matching the deployment network, correct collateral inputs, and any reference scripts or inputs the validator expects. Treat this as a starting point, not a copy-paste procedure.

**Guideline:** Compare before/after ExUnits using the network parameters that matter to the deployment target. Avoid hard-coded ExUnits thresholds in advice unless the project has already pinned those protocol parameters and confirmed them against the deployment network.

---

## OPT-11: Choose Data Traversal Patterns for the Actual Hot Path

**Why it matters:** The right choice depends on the size and frequency of the collection you inspect, not on a universal rule.

**Common heuristics to test:**
- Pattern matching is often cleaner and faster when exact shape is expected
- Repeated `filter` then `head` is usually worse than a single pass
- Small collections may not justify more abstract structures

**Example:**
```haskell
case txInfoInputs info of
  [singleInput] -> validateSingle singleInput
  _             -> traceError "expected one input"
```

**Relationship to P6 (Improper Input Constraints):** The pattern-match form above is also the recommended security fix in P6 for single-input semantics — it binds the element and enforces exact count in one expression. The security and performance recommendations are aligned here: prefer `case filteredInputs of [x] -> ...` over `length filteredInputs == 1` followed by a separate lookup.

**Alternative single-pass helper:**
```haskell
findFirst :: (a -> Bool) -> [a] -> Maybe a
findFirst _ [] = Nothing
findFirst p (x:xs) = if p x then Just x else findFirst p xs
```

**Profiling note:** Treat "lists vs maps vs assoc maps" as a benchmark question once the hot path is known.

---

## OPT-12: Consider Plutus V3 Data-Representation Wins Only for Projects Already Targeting V3

**Why it matters:** Plutus V3 changes the available language/runtime surface, and some ADT-heavy code may compile more efficiently under a V3-compatible toolchain.

**When to recommend it:**
- The project already targets Plutus V3, or upgrading is already planned
- The validator is heavy on algebraic data types or constructor-heavy logic

**When not to overstate it:**
- Do not recommend a V3 migration as a default micro-optimization
- Do not quote fixed percentage savings without compiled-script evidence

**Guideline:** Treat V3 optimization as version-specific. Confirm with the project's actual compiler settings, generated script size, and ExUnits measurements.

---

## Common ExUnits Budget Diagnoses

Use this table as "what to check next", not as a deterministic root-cause map.

| Symptom | Common things to check next | Typical directions |
|---|---|---|
| Budget grows sharply with more inputs | repeated list traversals, repeated decoding, per-input script duplication | OPT-2, OPT-3, architectural redesign |
| Large datum makes spends expensive | eager decoding, large inline state, repeated semantic checks | OPT-1, OPT-9, smaller datum schema |
| Multi-script transaction fails near budget | cumulative ExUnits across scripts, oversized witnesses | OPT-8, smaller policies, split flows |
| Script size grows unexpectedly | extra traces, eager data conversions, broad dependency surface | OPT-5, OPT-6, OPT-7 |
| Testnet looks fine, deployment target is tight | different parameters, different transaction shape, bigger real data | profile with deployment-like transactions |

---

## Performance Coverage Checklist

When reporting a performance analysis, explicitly state which of the following cost drivers were examined and what evidence basis was used (measured, structurally obvious, or hypothesized):

| Cost driver | Checked? | Evidence basis |
|---|---|---|
| Hot decode paths (datum, redeemer, context) | | |
| List traversal count and depth | | |
| Script size (byte count, trace contribution) | | |
| ExUnits on heaviest realistic paths | | |
| Multi-script cumulative cost | | |
| Datum and value size impact | | |
| Version-specific features in scope | | |

Label each unchecked driver explicitly. Unchecked drivers are not confirmed safe — they are outside the scope of the current static review.
