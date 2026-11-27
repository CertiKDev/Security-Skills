---
name: audit-cashscript-general
description: Audits CashScript contracts on Bitcoin Cash for CashTokens authority leaks (minting and mutable NFT containment, single-use credentials, token-only authentication), multi-contract transaction composition, commitment encoding, time and period logic, oracle and reserve economics, and VM, dust and compiler pitfalls. Produces a findings.md report with ranked vulnerabilities.
when_to_use: |
  Use when user mentions "CashScript", "cashc", ".cash contract", "CashTokens", "Bitcoin Cash smart contract", "BCH covenant", "BCH DeFi", "P2SH32", "token category", "minting NFT", "mutable NFT", "nftCommitment", "tokenCategory", "this.activeInputIndex", "tx.inputs[", "tx.outputs[", "LockingBytecodeP2SH32", "LockingBytecodeNullData", "unsafe_bytes", "toPaddedBytes", "checkDataSig", "tx.locktime", "this.age", "sidecar", "function NFT", "price thread", "OP_INVOKE", "OP_BEGIN", "BCH_2026_05", "MockNetworkProvider", "TransactionBuilder" with "cashscript", "@bitauth/libauth", or asks about Bitcoin Cash covenant security, CashTokens authority, or UTXO DeFi (stablecoin, lending, AMM, staking pool) built on BCH.
  Do NOT use for Bitcoin (BTC) Taproot, Miniscript or PSBT flows (use audit-psbt-security), Ordinals/Runes (use audit-btc-marketplace-general), Clarity/Stacks, Solidity/EVM, or Lightning.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Write
arguments:
  - target
argument-hint: "[directory of .cash contracts, artifacts and docs, or a description of the system]"
# context: inline (user interaction needed for findings review)
---

# CashScript / CashTokens Contract Vulnerability Scanner

## 1. Introduction

CashScript compiles to Bitcoin Cash Script. A contract is a UTXO; "calling" another contract means spending it in the same transaction; every input's script runs on its own and sees the whole transaction only through introspection. Whatever a script does not pin, the transaction builder chooses: extra inputs, extra outputs, tokens on those outputs, the index of each contract, the function selector, the thread of a threaded contract, and `tx.locktime`. Authority is token possession: a minting NFT can create any NFT of its category in the same transaction, and each mutable NFT can create one. Most serious CashScript bugs are therefore not inside one function. They sit between co-spent contracts, in an output nobody pinned, or in an economic assumption the UTXO model cannot enforce.

Incidents and evidence informing this checklist:
- **ParyonUSD V1** (fixed 2026-10-08, block 972,003; never exploited): the borrow path accepted a loan's origin-proof NFT by category and position but never required it to be destroyed. A borrower could keep the proof and open a second loan with an existing loan's id; settling a redemption against one copy left both loans unliquidatable and exempt from interest, a bad-debt risk on any price drop. Found by an AI-assisted review of the next version and confirmed with formal verification after it had passed audits. Fixed by migrating every price thread to code that filters the borrow's free outputs. The same post-audit round added an explicit burn of a mutable NFT that could re-emerge on a user output at loan close, a CLTV prologue so `tx.locktime` is always enforced, oracle message length and positive-price checks, and corrected a fee multiplier applied in the wrong direction.
- **Production CashScript DeFi audits (2026)**: recurring issues in a collateralized stablecoin system included oracle-thread choice by the spender, no staleness bound on the oracle, privileged signer and migration reach, a fixed and fragmented reserve that can halt settlement, a rounding residue that blocks a zero-stake branch, and a relative timelock that any party can restart. The errors that most often distort first-draft findings are listed in `references/finding-validation.md`.
- **Community covenant design notes** (Bitcoin Cash Research forum; CashScript adversarial guide): unrestricted outputs beyond the pinned ones are claimable by anyone; stale-state arbitrage and race double spends on unconfirmed chains; anyone-can-claim bounties invite double-spend tooling.

No public CashScript exploit with measured losses is documented as of November 2026. Rate severity from the reach of the authority or value involved, not from incident history.

## 2. Purpose

This skill audits CashScript systems to detect:

- Authority leaks: minting and mutable NFT containment, forged function or credential NFTs, single-use tokens that survive, token-only authentication
- Composition flaws: unpinned indices and outputs, sidecar pairing, selector choice, double satisfaction across co-spent covenants
- State encoding flaws: commitment layouts, signed decoding, `unsafe_bytesN`, `toPaddedBytes` widths, rounding and zero divisors
- Time flaws: unenforced or backdated `tx.locktime`, resettable relative timelocks, period clocks that catch up or accrue only when reported
- Economic flaws specific to UTXO DeFi: oracle thread choice and staleness, fixed fungible supply and reserve fragmentation, privileged migration
- Liveness: dust, VM cost, standardness, contention, states where every path fails
- Build integrity: compiler version and options, artifacts versus source, constructor argument encoding

---

## 3. When to Use This Skill

**Prompt trigger**

```
Does the project contain .cash files or `pragma cashscript`? ──yes──> Use this skill
│
no
│
v
Does it deploy covenants on Bitcoin Cash or use CashTokens (categories, NFT capabilities, commitments)? ──yes──> Use this skill
│
no
│
v
Does TypeScript code import `cashscript`, `cashc` or `@bitauth/libauth` to build contract transactions? ──yes──> Use this skill
│
no
│
v
Skip this skill
```

**Concrete triggers**

- `pragma cashscript`, `contract X(...) { function f(...) { ... } }`
- `tx.inputs[i].tokenCategory`, `tx.outputs[i].nftCommitment`, `tokenAmount`, `lockingBytecode`, `value`
- `this.activeInputIndex`, `tx.inputs.length`, `tx.outputs.length`, `outpointTransactionHash`, `outpointIndex`
- `+ 0x01` / `+ 0x02` capability suffixes, `CAPABILITY_MINTING`, `CAPABILITY_MUTABLE`
- `unsafe_bytes32(...)`, `int(bytes)`, `toPaddedBytes(x, n)`, `.split(n)`, `.slice(a, b)`
- `tx.locktime`, `tx.time`, `this.age`, `sequenceNumber`, `tx.version`
- `checkDataSig`, `checkSig`, `new LockingBytecodeP2SH32(...)`, `new LockingBytecodeNullData(...)`
- Artifacts with `OP_DEFINE`, `OP_INVOKE`, `OP_BEGIN`, `OP_UNTIL`; `compiler.options` in artifact JSON
- TypeScript: `new Contract(artifact, args, { provider })`, `new TransactionBuilder({ provider })`, `addInput`, `addOutput`, `MockNetworkProvider`, `toFailRequire`

## Additional resources

- Language, VM and token semantics with grep patterns (B-01 to B-35) and a per-function review card: [cashscript-vm-baseline.md](references/cashscript-vm-baseline.md)
- How to prove authority containment across co-spent contracts: [authority-containment-method.md](references/authority-containment-method.md)
- Economic and liveness patterns E-01 to E-12 with quantification and enforceable fixes: [utxo-defi-economic-patterns.md](references/utxo-defi-economic-patterns.md)
- Refutation checklist, unenforceable recommendations and severity calibration: [finding-validation.md](references/finding-validation.md)
- SDK, build and test pitfalls: [typescript-vulnerable-patterns.md](references/typescript-vulnerable-patterns.md)

---

## Goal

Produce a `findings.md` file containing every confirmed vulnerability in the target CashScript system, each with a title, code location, description, attack scenario and recommendation, ranked by severity. Every checkpoint below must be evaluated against the whole system, not one file at a time. The audit is complete when the transaction-shape map covers every function, every checkpoint has a verdict, and every reported finding has survived the refutation pass.

## Workflow

### Step 1: Establish scope and baseline
List the `.cash` files, artifacts, deployment parameters and design docs. Record the cashc version, the compiler options in the artifacts, and the VM target. Read every contract in full, in dependency order: shared constants, oracle and migration, reserve or factory contracts, position contracts and their function contracts, then pool or settlement contracts.

**Artifacts**: file list with line counts, compiler version and options, trust assumptions from the docs (oracle, migration key, keepers, genesis)
**Success criteria**: every in-scope file has been read end to end; line numbers are taken from per-file listings.

### Step 2: Build the transaction-shape map
Apply checkpoint `0x0000`. Build the per-function map, the acceptance-site matrix and one capability containment table per category, following `references/authority-containment-method.md`.

**Artifacts**: per-function map; acceptance-site matrix; containment tables
**Success criteria**: every function of every contract has a row; every minting or mutable capability, including user categories, has a table.

### Step 3: Execute checklist
Evaluate checkpoints `0x0001` to `0x0016` against the map. For each, follow Identify, Analyze, Exploitability and Check. Use the per-function review card in `references/cashscript-vm-baseline.md` for line-level checks.

**Artifacts**: per-checkpoint verdict: candidate finding, `not applicable` with justification, or `safe` with the `file:line` that makes it safe
**Success criteria**: every checkpoint has a verdict tied to code.

### Step 4: Refute and quantify
Run every candidate through `references/finding-validation.md`: write the concrete transaction, run every co-spent script, try to refute it, quantify impact under stated assumptions, and check that the recommendation is enforceable in BCH script. Merge candidates that share a root cause.

**Artifacts**: confirmed findings with severity; rejected hypotheses with the check that stops each; leads that need a test
**Success criteria**: no finding relies on an unread script, an unenforceable fix, or an unquantified severity.

### Step 5: Compile findings
Collect confirmed findings into `findings.md` using the output format below, most severe first.

**Artifacts**: `findings.md`
**Human checkpoint**: present the draft findings, the rejected hypotheses and the deployment trust assumptions to the user before writing the file.
**Success criteria**: the user has reviewed and approved the findings.

## Output Format

Each finding in `findings.md` must contain these five sections:

**Title**: `{Some Issue Or Flaw} Leads To {Some Outcome}`. Capitalize every word except prepositions.

**Code location**: `filename-L{start}~L{end}`, placed above the description, with the unfollowed checkpoint ID. List every file in the transaction shape that the finding depends on.

**Description**: Start with the severity (Critical, Major, Medium, Minor or Informational). Describe the functions' purpose, the transaction shape, the issue and the quantified impact. Use clear narrative; enclose functions and variables in backticks.

**Scenario**: Numbered steps with fictional actors (Alice, Bob). Name the inputs and outputs of each transaction and why every script in it passes.

**Recommendation**: A fix that BCH script can enforce, with the cost it adds (contention, extra inputs, layout changes).

## Rules

- Do not report a finding without a concrete code location and a concrete transaction.
- Do not report an output, index or path as unconstrained before reading every script that runs in that transaction shape.
- Do not skip a checkpoint. Mark it `not applicable` with a justification, or `safe` with the `file:line` that makes it safe.
- Do not rely on a VM limit failing, on standardness for safety, or on 40-byte commitments or 64-bit overflow.
- Do not recommend a time upper bound, a read-only input, or a check that another line already enforces.
- Report deployment and genesis invariants that the code does not enforce as explicit trust assumptions.
- Pause for user confirmation before writing `findings.md`.
- If a checkpoint touches another skill's domain (wallet PSBT signing, for example), note the cross-reference by checkpoint ID but do not execute the other skill.

---

## 4. Checklist

### Title: 0x0000-transaction-shape-map-must-exist-before-any-function-is-judged

Description
In CashScript the unit of security is the transaction, not the function. A function that looks safe alone can be unsafe in a shape where another contract leaves a capability budget free, and a function that looks unsafe can be fully constrained by a co-spent sibling. Judging functions before mapping transaction shapes produced most of the wrong first-draft findings in past audits, in both directions.

Identify
1. For every contract and function, find `this.activeInputIndex` checks, every `tx.inputs[i]` and `tx.outputs[i]` read, `tx.outputs.length` bounds, and every capability-bearing token the function spends or requires.
2. Find every place a contract authenticates another by token, bytecode or adjacency, and record which contracts must run together.
3. Find every NFT capability in the system, including categories minted for users (position keys, receipts, credentials).

Analyze
1. Build the per-function map in `references/authority-containment-method.md` section 1.
2. Build the acceptance-site matrix (section 2) and one containment table per minting or mutable category (section 3).
3. Mark the cells excluded only by genesis; these become trust assumptions.

Exploitability
1. For each function, ask what a builder can add: an extra input carrying another capability, an extra output, a sibling function, a second instance, an older state UTXO, another thread.
2. Any empty cell in a containment table is a candidate authority leak for checkpoints `0x0002` to `0x0005`.

Check
1. Every function of every contract has a map row with per-file line numbers.
2. Every capability has a containment table with a verdict per spender.
3. Later checkpoints cite map rows rather than single lines.

---

### Title: 0x0001-token-authentication-must-match-category-capability-and-non-empty-commitment

Description
`tokenCategory` returns 32 bytes for FT-only and immutable NFTs and 33 bytes with the capability byte for mutable or minting NFTs. An immutable NFT with an empty commitment is indistinguishable from an FT-only output. A check on the bare category therefore also accepts plain fungible tokens and junk empty NFTs, and a check without the capability byte accepts a weaker token where a stronger one was meant (baseline B-01, B-02, B-04, B-07).

Identify
1. Find every `tokenCategory ==` comparison and every `split(32)` on a category.
2. Find every commitment check: exact value, prefix byte, length, or none.
3. Find outputs pinned by category without `tokenAmount == 0` or without a commitment check.

Analyze
1. For each acceptance site, list what satisfies it: genuine token, FT-only of the category, empty-commitment NFT, another capability of the category, a token minted in this transaction.
2. Determine whether any protocol-category token is ever created with an empty commitment or whether the category has FT supply.
3. Check whether outputs that should carry only FT can receive an NFT, and the reverse.

Exploitability
1. Determine whether plain fungible tokens satisfy a check that was meant to require an NFT credential, for example "the transaction must include a protocol token" used as a spam or consumer gate.
2. Determine whether an empty or minted junk NFT can stand in for a state or function NFT.

Check
1. Credentials are authenticated by category with capability byte and a non-empty expected commitment or prefix.
2. FT-only outputs require an empty commitment where an NFT would matter; NFT-only outputs require `tokenAmount == 0`.
3. No contract authenticates on an empty commitment.

---

### Title: 0x0002-every-minting-nft-spend-must-bound-outputs-and-filter-every-free-slot

Description
A minting input lets its transaction create any number of NFTs of that category with any commitment and capability, including new minting NFTs. Containment requires that every output is pinned or filtered for that category and that the output count is bounded. Filters written only for protocol categories miss user categories that are also spent with minting capability, such as a newly minted position key (baseline B-03, B-14).

Identify
1. Find every function that spends a minting NFT of any category, including factories that mint user credentials and contracts that share a minting NFT (a pool and the payouts it creates).
2. For each, list pinned outputs, free outputs and their filters, and the `tx.outputs.length` bound, and note which script enforces each.
3. Find every transaction shape in which the minting input appears.

Analyze
1. Fill the containment table for the category. A spend is contained only if all outputs are pinned or filtered for the category and the output count is bounded in every shape.
2. For free outputs, check which categories the filter covers. A filter on the protocol token does not stop extra NFTs of a user category minted in the same transaction.
3. Check whether any function that holds the minting NFT has no output bound at all and relies on another contract's bound.

Exploitability
1. Determine whether a builder can add an output carrying a new minting NFT, a forged function or state NFT, or a duplicate credential.
2. Assess what the forged token authorizes elsewhere: a fake payout inflating receipts, a hidden minting copy of a position key surviving a transfer of the position, a forged function NFT.
3. Do not dismiss copies of a user's own minting key as "the owner could mint them anyway". A copy emitted in the transaction that creates or modifies the position is invisible to a later buyer or delegate of that position, and the copy keeps full owner rights after the transfer.

Check
1. Every minting spend has a bounded output count in every shape.
2. Every free output is filtered for every category minted or held in the transaction.
3. Every holder of a shared minting NFT is analysed as a spender.

---

### Title: 0x0003-every-spent-mutable-nft-must-be-recreated-or-burned-at-a-pinned-output

Description
Each mutable input gives its transaction a budget of one new NFT of that category. If the function consumes the mutable NFT without re-creating it at a category-pinned output, or without an explicit category-pinned burn, the free budget can surface on any unpinned output as a new mutable or immutable NFT with any commitment. Close, liquidate and finalize paths are where this happens, because they intend to destroy the token (baseline B-03, B-06).

Identify
1. Find every function that spends a mutable NFT (state UTXOs, positions, collectors, oracle threads).
2. For each, find the output that re-creates it, or the `OP_RETURN` output that burns it, and check that the output pins the category with the capability byte.
3. Find burn outputs that check only `lockingBytecode == 0x6a` or only the bare category.

Analyze
1. For close and liquidation paths, determine whether the mutable budget is consumed by a pinned output or left free.
2. If several mutable inputs of one category are spent, check that each is accounted for.
3. Check whether any output in the shape is free to receive that category.

Exploitability
1. Determine whether a position NFT can re-emerge on a user-controlled output after close, with a forged commitment (zero debt, another owner).
2. Assess what that forged state authorizes: withdrawing collateral, redeeming, liquidating someone else.

Check
1. Every mutable input is re-created at a pinned output or burned at an output that pins `category + 0x01` and `OP_RETURN`.
2. Functions without an output bound document why no free budget exists in any shape.

---

### Title: 0x0004-single-use-credentials-must-be-consumed-in-the-transaction-that-uses-them

Description
Protocols mint one-time tokens to prove that a position was created correctly, for example an origin proof minted together with a position key. The invariant "each proof backs exactly one position" holds only if the transaction that uses the proof also destroys it. If the proof is accepted by category and position alone and no output pins where it goes, it survives and can back a second position with the same identifier. ParyonUSD V1 shipped with this bug: two loans with one id could be toggled so neither was liquidatable (`references/authority-containment-method.md` section 5).

Identify
1. Find every token minted as a proof, ticket, voucher, receipt or origin marker, and every place it is accepted.
2. For each acceptance, find the output that burns or re-pins it, and the filters on free outputs for its category.
3. Find every lookup by identifier (position id, stake id) and what assumes identifiers are unique.

Analyze
1. Trace the proof through every transaction shape that accepts it. If any shape lets it leave on a free output, it is reusable.
2. Check whether a second position with a duplicate identifier is distinguishable by any contract that looks positions up by id.
3. Check whether the fix (if any) is placed in code that every relevant transaction runs, such as every thread of a threaded contract.

Exploitability
1. Alice creates a position and keeps the proof on a free output; she uses it with a new key to create a second position with the same id.
2. Determine what the duplicate enables: settling a redemption, claim or liquidation against the wrong copy, freezing both, double-claiming rewards.

Check
1. Every single-use credential is burned to `OP_RETURN` or provably consumed in the transaction that uses it.
2. Free outputs of that transaction refuse the credential's category or allow only the intended capability-free tokens.
3. Uniqueness of identifiers is stated as an invariant and enforced, not assumed.

---

### Title: 0x0005-function-nft-and-token-only-authentication-must-rest-on-provable-genesis-invariants

Description
Many CashScript systems keep a thin top-level contract that only requires a sidecar at `+1` and a function NFT at `+2`, and move all logic into function contracts identified by an immutable NFT. Token-only authentication trusts everything that can create that token. Security then rests on genesis distribution (which function NFTs exist and where they sit) and on containment of every capability of that category. Neither is checked by the code (baseline B-15, B-22).

Identify
1. Find authentication by category and commitment length or prefix without a `lockingBytecode` check.
2. Find genesis and deployment documents: which NFTs were minted, to which scripts, with which commitments and lengths.
3. Find contracts that read state with `unsafe_bytesN` and depend on genesis lengths.

Analyze
1. For each token-authenticated component, list who can create a token that passes the check: genesis, any minting holder, any free mutable budget.
2. Check whether a wrong genesis placement (a function NFT at the wrong script) gives its holder full control of the contract it authorizes.
3. Determine whether any state length error self-heals at a normalizing writer or persists through length-preserving writers.

Exploitability
1. Determine whether a forged or misplaced function NFT lets an attacker run arbitrary logic in place of a function contract.
2. Assess the blast radius: every position of a type, or one.

Check
1. Every token-only authentication site is listed as a trust assumption with the genesis fact it relies on.
2. Deployment can be verified on chain: function NFT locations, commitment lengths, category byte order.
3. Where cheap, authentication pins the script or a positive identity (exact length, state prefix) instead of relying on exclusion elsewhere.

---

### Title: 0x0006-active-input-index-must-be-pinned-and-counterpart-indices-derived-from-it

Description
Each input's script runs separately. A function that does not pin `this.activeInputIndex`, or that reads counterparts at absolute indices unrelated to its own, can be satisfied at an unexpected position or by two instances of the same contract that both check one counterpart (baseline B-10, B-11).

Identify
1. Find every `this.activeInputIndex` check and every function without one.
2. Find reads of `tx.inputs[k]` with a constant `k` and whether `k` is derived from the active index.
3. Find contracts that can appear more than once in one transaction (positions, vaults, receipts).

Analyze
1. For unpinned functions, determine at which indices the function can run and which counterpart it checks from each.
2. Check whether two instances can share one counterpart, one payment output or one sidecar.
3. Write the index conflicts that exclude co-execution explicitly ("A needs index 0, B needs index 0").

Exploitability
1. Determine whether Alice can spend two positions in one transaction while only one is checked, or satisfy two covenants with one counterpart.
2. Assess whether batch functions (claims, merges) can process one entry twice.

Check
1. Every function pins its index or derives every other index from it.
2. Batch functions bind each entry to its own index and output.

---

### Title: 0x0007-sidecar-adjacency-must-hold-for-every-transaction-that-creates-the-primary

Description
Sidecars (a second UTXO holding FT or extra state for a primary NFT UTXO) are paired by outpoint adjacency: same transaction hash, consecutive output index. This proves only that both were created by one transaction at consecutive indices. It is sound only if every transaction that creates or re-creates the primary also pins its genuine sidecar at the adjacent index, and the sidecar itself checks what sits next to it (baseline B-12).

Identify
1. Find every `outpointTransactionHash` and `outpointIndex` comparison.
2. List every function that creates or re-creates each primary UTXO.
3. Find sidecar contracts and what they check about the primary (category, commitment, index).

Analyze
1. For each creator, confirm the sidecar output is pinned at index + 1 with the expected token and script.
2. Check whether a sidecar reads a function or state commitment without checking its category.
3. Check whether a primary can be re-created at a different index than it was spent from, breaking the sidecar's re-pin condition.

Exploitability
1. Determine whether Bob can pair a genuine primary with an attacker-built sidecar (or the reverse) in a creator that does not pin the sidecar.
2. Assess what the mismatched pair lets Bob withdraw or claim.

Check
1. Every creator of a primary pins the sidecar adjacently.
2. Sidecars authenticate the primary by category with capability, not by commitment alone.

---

### Title: 0x0008-free-outputs-must-not-carry-authority-value-or-satisfy-a-second-covenant

Description
Outputs a script does not pin are chosen by the builder. They can carry foreign tokens, protocol tokens, NFTs created from any free budget, and leftover BCH. Two covenants can also each be satisfied by the same output, the classic double satisfaction (baseline B-07, B-14; `references/utxo-defi-economic-patterns.md` E-09).

Identify
1. For each transaction shape, list outputs left free for users (change, frontend fees, delegated managers) and their filters.
2. Find requirements of the form "some output pays X to Y" or "an output exists with token T" without an index.
3. Find covenant-only transactions with no signed input, and unread unlocking arguments.

Analyze
1. Determine what each free output can carry given every capability in the shape.
2. Determine whether two scripts in one transaction can be satisfied by one output or one input.
3. Determine where unpinned BCH goes and whether an unsigned transaction's outputs can be redirected or its txid malleated.

Exploitability
1. Determine whether Bob can route a protocol token, a credential, or a reward to himself through a free output.
2. Assess whether Bob can pay once and satisfy two payment covenants.
3. Assess whether a miner or relay can change a keeper's reward output or break a chained batch through malleability.

Check
1. Free outputs are filtered for every category present in the shape.
2. Payment checks bind to fixed indices.
3. Keeper rewards, change and unread arguments are pinned or fixed-size.

---

### Title: 0x0009-multi-function-contracts-must-be-safe-under-every-selector-choice

Description
A multi-function contract dispatches on a selector the spender chooses. When a protocol expects function `f` of a co-spent contract, the builder may choose sibling `g` instead. Each sibling must fail in shapes meant for the others, or be harmless there (baseline B-33).

Identify
1. List every multi-function contract and every place another contract expects it at a fixed index.
2. For each expected function, list the siblings.

Analyze
1. For each sibling, determine whether its checks pass in the expected shape.
2. If a sibling passes, determine what it changes (state, outputs) compared with the expected function.

Exploitability
1. Determine whether Bob can run a cheaper or weaker sibling (a roll instead of a settlement, a share instead of an update) and skip a required effect.

Check
1. For every expected function, each sibling is shown to fail in that shape, with `file:line`, or to be harmless.

---

### Title: 0x000a-commitment-layouts-must-match-every-writer-including-genesis

Description
State lives in NFT commitments of up to 128 bytes. Readers slice fixed offsets and cast with `unsafe_bytesN`, which checks nothing. A layout is safe only if every writer, genesis included, produces the same widths and encodings that every reader expects. Writers that rebuild state from `split` remainders preserve a wrong length forever (baseline B-08, B-19, B-21, B-22, B-23, B-24).

Identify
1. For each state NFT, write the layout: offset, width, signedness, meaning.
2. List every writer (including genesis and migration) and every reader of that layout.
3. Find variable-length fields (`bytes(int)`, hashes of two possible sizes) and their positions.

Analyze
1. Check each reader's offsets and widths against each writer.
2. Classify writers as normalizing or length-preserving and run the length induction from genesis.
3. Check byte equality on numeric fields for a single encoding across writers.
4. Check that a variable-length field is last and that `bytes(0)` producing an empty field is accepted or rejected consistently.

Exploitability
1. Determine whether Bob can create or keep state of an unexpected length that shifts later fields, or whether a wrong genesis length persists.
2. Assess whether a proposed new field breaks readers that use `split(k)[1]`.

Check
1. Every reader matches every writer.
2. The length induction from genesis holds, or normalizing writers repair it.
3. Numeric fields compared as bytes use one fixed-width encoding everywhere.

---

### Title: 0x000b-signed-decoding-and-state-subtractions-must-be-range-checked

Description
`int(bytes)` is signed: a set top bit decodes as negative. `toPaddedBytes` stores a negative number without complaint and fails only when the value is too wide. `int` function parameters get no compiler check. Subtractions written to state therefore need explicit `>= 0` checks, and widths must cover the largest reachable value (baseline B-16, B-17, B-19, B-20).

Identify
1. Find every `int(...)` on state, parameters or oracle data.
2. Find every subtraction whose result is written with `toPaddedBytes` or compared later.
3. Find every `toPaddedBytes(x, n)` and the maximum reachable `x`, including prices, volumes and products.

Analyze
1. Determine whether each decoded value can be negative or larger than intended.
2. Determine whether each stored subtraction is proven non-negative by a check or an invariant.
3. Compute the value at which each width overflows (for example a 4-byte price field above about 2^31 base units).

Exploitability
1. Determine whether Bob can pass a negative amount or price that inverts a comparison or a payment direction.
2. Determine whether a market move or accumulated volume can push a value past its width and make a function fail for everyone.

Check
1. Every signed read used in a comparison or payment is range-checked.
2. Every subtraction written to state is checked `>= 0`.
3. Every width is sized for the maximum reachable value, and oracle inputs require `price > 0` and exact message length.

---

### Title: 0x000c-division-rounding-and-shared-formulas-must-agree-across-contracts

Description
`/` truncates toward zero and fails on zero. In multi-contract systems the same quantity (a fee split, a reservation, a pro-rata share) is computed in several contracts that must agree to the unit. Rounding direction decides who keeps the dust, and repeated floors leave residues (baseline B-18; E-05).

Identify
1. Find every `/` and `%` and its divisor's source.
2. Find quantities computed in more than one contract and compare the expressions.
3. Find pro-rata and roll-forward formulas (shares, receipts, earnings) and their rounding direction.

Analyze
1. Check each divisor for a reachable zero.
2. Check that shared quantities use identical expressions in every contract that must agree.
3. Compute the maximum gain from rounding per operation and whether merging, splitting or ordering operations changes it.

Exploitability
1. Determine whether Bob gains by splitting or merging positions before a roll, or by ordering operations.
2. Determine whether a one-unit disagreement between two contracts makes a required transaction impossible.

Check
1. Divisors are positive or guarded.
2. Shared formulas are identical across contracts.
3. Rounding favours the protocol, and its maximum per-operation effect is documented.

---

### Title: 0x000d-no-reachable-state-may-make-every-spend-path-fail

Description
A covenant is bricked, not just slowed, when every spend path is consensus-invalid in some reachable state: a zero divisor, a width overflow, a negative value, a branch chosen on exact zero that a rounding residue never reaches, or a position scaled to zero that cannot exit. Unlike standardness problems, a miner cannot rescue these (baseline B-29, B-30; E-05).

Identify
1. For each contract, list the conditions under which each function fails for everyone, not just for one caller.
2. Find branches chosen on exact values (`== 0`, `== total`) of amounts built with floor division.
3. Find exit paths that divide by a total that can reach zero.

Analyze
1. Determine whether the protocol can reach a state where all branches fail: all users exited but a residue remains; a position slashed to zero; a counter at its width limit.
2. Determine the fallback (unanimous exit, migration, sweep) and whether one actor can block it.

Exploitability
1. Determine whether Bob can push the system into the stuck state cheaply, or whether ordinary use reaches it.
2. Assess what is frozen: deposits, rewards, positions.

Check
1. Branches key on "no live positions" or on bounded thresholds, not on exact amounts with residue.
2. Every exit path works for zero-sized and last positions.
3. No reachable state disables every function.

---

### Title: 0x000e-absolute-locktime-must-be-enforced-and-backdating-must-be-harmless

Description
`tx.locktime` is a number the spender chooses. Consensus enforces it only if some input is non-final; cashc 0.13+ injects a CLTV guard when a function reads it, but the 500,000,000 boundary between heights and timestamps must still be checked by hand. A script can prove only that at least height H has passed, so any value read from `tx.locktime` may be backdated to any past height (baseline B-25).

Identify
1. Find every `tx.locktime` and `tx.time` use, and confirm in the artifact ASM that each reading function starts with `OP_TXLOCKTIME OP_CHECKLOCKTIMEVERIFY OP_DROP`.
2. Find where `tx.locktime` is stored into state (fee clocks, period starts, timestamps).
3. Find logic that treats `tx.locktime` as "now".

Analyze
1. Check that the guard exists and that heights and timestamps cannot be mixed.
2. For every stored or compared locktime, compute the effect of the smallest acceptable value (backdating).
3. Check that no recommendation or design relies on an upper bound ("only before T").

Exploitability
1. Determine whether Bob gains by backdating: lower elapsed time on a fee or interest clock, an earlier start for a timelock, or skipping a decay.
2. Determine whether a transaction with all-final inputs lets a function run with an unenforced locktime.

Check
1. The CLTV guard is present for every reader and the 500M boundary is checked.
2. Backdating is bounded by a stored floor and its maximum effect is documented.
3. No safety property depends on proving a time upper bound.

---

### Title: 0x000f-relative-timelocks-must-not-be-resettable-by-permissionless-recreation

Description
`this.age` and exact `sequenceNumber` checks measure time since the UTXO was created. Any function that re-creates that UTXO restarts the clock. If a third party or the beneficiary can re-create it freely (a swap, a re-target, a top-up), a waiting period can be extended indefinitely or turned into a free option on price (baseline B-26; E-06).

Identify
1. Find every `this.age`, `sequenceNumber` and `tx.version == 2` check.
2. For each UTXO protected by a relative lock, list every function that spends and re-creates it, and who may call each.
3. Check other-input relative locks for exact equality, not `>=`.

Analyze
1. Determine whether any permissionless or counterparty-controlled function re-creates the locked UTXO.
2. Do not stop at ordering rules that make each move "strictly better" or a chain "short". Ask whether the attacker can prepare the chain: a ladder of their own positions ranked between the start and the victim, or a permissionless state refresh (an interest or period update) that makes a prepared position eligible after the claim started.
3. Do not accept "anyone can settle or cancel" as the defence until you name who else has the incentive and the timing to act. When the attacker controls both sides of the claim, settling early only moves their own funds; a passive counterparty does nothing.
4. Determine whether the lock value is in 1..65535 with type bit 22 as intended and enforced on chain, not only by a constructor comment.

Exploitability
1. Determine whether Bob can keep resetting a settlement timer to delay the counterparty, or park a claim on his own positions and move it onto the victim only when the price favours him.
2. A price locked at start plus the ability to delay settlement or cancel at a boundary is an option even without any re-creation. Value it (for example by simulation at realistic volatility) for the passive case and the laddered case, and compare with the documented bound.

Check
1. Waiting periods that must survive re-creation are measured from a start height stored in state.
2. Relative lock checks use exact sequence equality plus `tx.version == 2`.

---

### Title: 0x0010-period-clocks-must-not-catch-up-in-one-block-or-copy-stale-periods

Description
Period-based systems advance a clock with `tx.locktime >= boundary(next)`, one period per transaction. After a lag, every catch-up step can run in one block, and anything dated "next period" during the lag earns rewards for periods in which it carried no risk. State copied from a stale thread backdates new positions the same way (E-08).

Identify
1. Find period-advance functions and their locktime condition.
2. Find where new positions are dated (`period + 1`) and where period values are copied from other UTXOs.
3. Find rewards distributed per period to whoever is staked in that period.

Analyze
1. Determine the maximum lag and whether catch-up can happen in one block.
2. Determine whether deposits made during the lag share catch-up rewards, and whether positions copy a stale period.
3. Determine whether the attacker can create the lag or only exploit it.

Exploitability
1. Alice deposits during a lag, runs or waits for the catch-up, collects the catch-up rewards and withdraws once current.
2. Quantify the gain as (lag − 1) periods of rewards times her share.

Check
1. Consecutive advances are separated by a relative timelock, or the behaviour is documented with an operational commitment to advance every period.
2. Positions are dated from the current state of the authoritative clock, not a caller-chosen thread.

---

### Title: 0x0011-debt-reducing-paths-must-settle-accrued-charges-first

Description
When interest or fees are charged only by a keeper function per reported period, every function that repays, closes, liquidates, redeems or withdraws collateral against the recorded amount forgives the unreported charges and evaluates margins against an understated debt (E-07).

Identify
1. Find the accrual function and the marker it updates (last period charged).
2. Find every function that reduces or removes the debt or checks a margin against it.
3. Find states that freeze the marker (pending redemptions or claims).

Analyze
1. Determine whether each debt-reducing function requires the marker to be current or adds outstanding charges.
2. Compute the forgiven amount per exit with a timely keeper and under lag, and the true margin after a withdrawal.
3. Check whether a repay, report, redraw cycle is profitable at the maximum rate.

Exploitability
1. Alice closes her position right after a period boundary and before the keeper reports it; the period's interest is never charged.
2. Assess whether liquidations trigger later than they should because eligibility uses the recorded debt.

Check
1. Debt-reducing paths include outstanding charges, or require the marker to be current, or the forgiveness is documented and bounded.
2. A maximum rate keeps the redraw cycle unprofitable.

---

### Title: 0x0012-fixed-supply-reserves-must-cover-every-mandatory-settlement

Description
Fungible supply is fixed at genesis. A protocol that holds its token in reserve UTXOs, burns repayments instead of returning them, and requires one reserve UTXO to release a whole settlement amount will halt when every thread is too small. Anyone can push threads down by borrowing and repaying (baseline B-04; E-04).

Identify
1. Find reserve contracts, their threads, and every path that releases or returns tokens.
2. Find mandatory settlements and the index from which they must source tokens.
3. Find tallies that grow without checking reserve liquidity (accrual, surcharges, carried-forward amounts).

Analyze
1. Determine whether settlement can draw from more than one thread.
2. Compute lifetime gross issuance against genesis supply and the cost to drain each thread deliberately.
3. Determine what stops when settlement halts and whether any fallback exists.

Exploitability
1. Bob borrows from each thread and repays (burning) in a loop until no thread covers the next settlement.
2. Assess the frozen funds and the cost of the attack at the deployed supply.

Check
1. Settlement can source from several threads, or threads can merge, or repayments return to the reserve.
2. The supply is sized far above lifetime issuance and the liveness condition is documented.

---

### Title: 0x0013-oracle-reads-must-bound-staleness-and-thread-choice

Description
Oracle prices arrive as signed messages (`checkDataSig`) stored in price UTXOs, often several threads for throughput. Consumers authenticate the price UTXO by token. Without a cross-thread order or a stored timestamp, the spender picks the most favourable thread; without a staleness latch, an outage leaves the last price usable forever. No script can prove that the oracle is late (baseline B-31, B-32; E-01, E-02).

Identify
1. Find the oracle update function: signature check, message layout, sequence and timestamp handling, length and sign checks.
2. Find every consumer and how it selects and authenticates a price UTXO.
3. Find what is stored in price state: price, sequence, timestamp, update height.

Analyze
1. Determine whether ordering is per thread only and whether consumers can choose among threads.
2. Determine whether any consumer bounds the price's age, and how a stale state could be detected with lower-bound time only.
3. Determine whether a signed message can be replayed into another thread or after a newer one.

Exploitability
1. After a price drop, Alice opens or keeps a position using the thread that still shows the old price; after a rise, Bob redeems against a stale low price.
2. During an outage, Alice borrows against a price above market and walks away.
3. Quantify the gain at realistic price moves and update intervals, and the counterfactual with all threads current.

Check
1. Threads are ordered globally or consumers require the freshest of several.
2. A stale-price latch exists that anyone can set after a window, and consumers honour it.
3. Messages require exact length and `price > 0`.

---

### Title: 0x0014-privileged-signers-and-migration-must-be-bounded-and-announced

Description
Oracle signers and migration keys sit above all contract logic. If consumers authenticate the price contract by token only, migrated code inherits everything the token is trusted for, including acting as a function NFT or releasing a minting NFT. A signer can publish any price. Without an on-chain notice period, users cannot exit first (E-03; `references/authority-containment-method.md` section 7).

Identify
1. Find every privileged key: oracle public keys, migration NFTs, admin tokens.
2. Find migration functions, their announcement and delay mechanisms, and destination constraints.
3. Find what consumers check about the migrated contract: token, state prefix, script.

Analyze
1. List what each key can do in one transaction and the total value it reaches.
2. Determine whether a notice period is enforced on chain and whether borrowers, not only liquidity providers, can act inside it.
3. Determine whether all threads must migrate together and whether one left behind reopens a fixed bug or blocks migration (thread count limits).

Exploitability
1. A compromised signer publishes a crashing price and liquidates every position, or an inflated price and drains the reserve.
2. A compromised migration key installs code that keeps the authority token and acts as a function NFT.

Check
1. Each privileged role is documented with its reach.
2. Migration has an enforced notice period and constrained destinations.
3. Price messages are bounded per update, or the signer is a threshold key.

---

### Title: 0x0015-dust-fee-vm-budgets-and-contention-must-not-block-core-functions

Description
Liveness depends on transactions that relay: outputs above dust for their real serialized size, unlocking bytecode within limits, loops within the operation-cost budget, and shared UTXOs that honest users can actually spend. Consensus-valid transactions that do not relay stop the protocol in practice; spam on a shared UTXO under first-seen relay delays everyone (baseline B-09, B-27, B-30, B-31; E-10, E-11).

Identify
1. Find fixed `value` pins and fixed fee or allowance deductions, and the size of each output's script and commitment.
2. Find loops, batch sizes and padding arguments, and the budget each needs.
3. Find shared UTXOs (oracle threads, pools, collectors) and functions anyone can call on them without a consumer.

Analyze
1. Compute dust per output with the token prefix and check every fixed value and every deduction floor.
2. Compute the per-input cost of the largest batch against `(41 + unlocking length) x 800` and the 10,000-byte standard unlocking limit.
3. Determine whether a spammer can keep a shared UTXO busy and how long honest updates are delayed under first-seen relay.

Exploitability
1. Determine whether repeated deductions push a UTXO below dust so it stops relaying, or below zero so every path fails.
2. Determine whether Bob can delay oracle updates or settlements with cheap spends.

Check
1. Every pinned value is at least dust for its real size, and deductions have floors.
2. Batch limits are measured on the current artifacts and current standardness rules.
3. Shared UTXOs have no free-standing permissionless function, or contention is bounded and documented.

---

### Title: 0x0016-artifacts-compiler-options-and-constructor-arguments-must-match-the-reviewed-source

Description
The contract on chain is the artifact compiled with specific options and instantiated with specific arguments. Compiler options can be silently disabled, build scripts can keep stale artifacts, token ids can be passed in explorer byte order, and the 2026 opcodes require the 2026 VM. A young compiler release is itself a risk for new code generation (baseline B-28, B-33, B-34, B-35; `references/typescript-vulnerable-patterns.md`).

Identify
1. Find the compiler version and `compiler.options` in every artifact, and the embedded `source`.
2. Find build and deployment scripts, constructor arguments and their encodings.
3. Find the test suite's VM target and how negative tests attribute failures.

Analyze
1. Rebuild with the pinned compiler and diff bytecode and embedded sources against the shipped artifacts.
2. Check token ids for VM byte order and locking-script arguments for full bytecode.
3. Check whether known compiler issues for the version (miscompiles, undefined options, `this.age` time units) touch patterns in the code.

Exploitability
1. Determine whether a deployed contract differs from the reviewed source or runs without the locktime guard or parameter checks.
2. Determine whether a mis-encoded argument makes a contract authenticate a category an attacker can create.

Check
1. Artifacts match the reviewed source byte for byte and record the expected options.
2. Constructor arguments are verified on chain against the documented values.
3. Tests run on the target VM, include adversarial transaction shapes, and attribute each expected failure to its contract and line.
