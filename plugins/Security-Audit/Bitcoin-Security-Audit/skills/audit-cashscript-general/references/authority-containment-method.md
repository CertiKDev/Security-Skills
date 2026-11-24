# Authority Containment Method for Multi-Contract CashScript Systems

CashScript protocols split one logical operation across several co-spent contracts. No single file shows whether authority leaks. This reference describes the method that proves containment or finds the leak. Checkpoints `0x0000` to `0x0009` in `SKILL.md` point here.

## 1. Build the transaction-shape map first

For every function of every contract, record one row before looking for bugs:

| Field | What to write |
|---|---|
| Contract.function | including the selector index |
| Own index | `this.activeInputIndex == k`, derived, or free |
| Inputs read | each `tx.inputs[i]` and what authenticates it: category + capability + commitment, `lockingBytecode`, or outpoint adjacency |
| Co-spent contracts | which other contracts must run in the same transaction, at which indices |
| Minting / mutable inputs | every capability-bearing input of every category in this transaction shape, including user categories |
| Outputs pinned | per index: `lockingBytecode`, category with capability, commitment, `tokenAmount`, `value` |
| Free outputs | indices left open and the filter applied to each, if any |
| Output bound | `tx.outputs.length <= N`, and which script enforces it |
| State fields | commitment offsets and widths read and written, signedness |

Write line numbers per file. Never derive them from a concatenated listing of several files; the offsets shift and every later citation is wrong.

## 2. Acceptance-site matrix

For each `require` that accepts a token or a UTXO as a credential, list every kind of UTXO that could satisfy it, then mark each one:

- **intended**: the genuine component;
- **rejected**: with the `file:line` of the check that rejects it;
- **excluded by genesis only**: no script rejects it; only the deployment invariant that such a token was never created keeps it out.

Kinds to try at every site: the genuine token; the same category with another capability; an FT-only output of the category; an empty-commitment immutable NFT; a token minted in this transaction from a free minting or mutable budget; the same token held by a different contract (one capability held by two contracts); a user-category token of the same shape; an older state UTXO of the same contract; another thread of a threaded contract.

The "excluded by genesis only" column is the list of deployment invariants the audit must report as trust assumptions. A credential identified by category and position alone, with nothing pinning where it goes afterwards, is the shape of the single-use credential bug in section 5.

## 3. Capability budget containment table

Build one table per category that has a minting or mutable NFT anywhere in the system.

| Spender (contract.function) | Capability spent | Re-created at | Free outputs and their filter for this category | Output bound | Verdict |
|---|---|---|---|---|---|

Rules for the verdict:

- A spent **minting** NFT is contained only if every output is pinned or filtered for that category **and** the output count is bounded (by this script or by a co-spent script that always runs).
- A spent **mutable** NFT is contained only if it is re-created at a category-pinned output, or explicitly burned to `OP_RETURN` with its category, or every free output is filtered for that category.
- Include **user categories** that the protocol mints for users, such as per-position keys. Protocol-category filters on free outputs do not filter a user category spent with minting capability in the same transaction; hidden minting copies of the user's key are the result.
- When a capability is held by more than one contract (for example a pool and every payout it creates), every holder is a spender and gets a row.
- Re-derive the table for every transaction shape that can co-spend extra capability inputs. A function with no output bound inherits whatever budget another input brings.

A forged copy of an authority NFT (for example a fake payout or a fake function NFT) breaks every contract that authenticates by category alone. Proving the table complete is how an audit shows that no such forgery exists.

## 4. Index and adjacency proofs

- **Fixed indices exclude double satisfaction.** If every function pins its own index and reads counterparts at fixed offsets, two instances of one contract cannot share a transaction and two covenants cannot both claim one counterpart. Write the conflict explicitly: "contract A needs index 0, contract B needs index 0 in the same shape, so they cannot co-run".
- **Selector choice.** For each multi-function contract co-spent at a fixed index, ask which sibling function the spender could choose instead, and show the check that makes each sibling fail in this shape.
- **Sidecar adjacency is an induction.** List every transaction that creates or re-creates the primary UTXO and confirm that each one pins the sidecar at index + 1 with the expected token. One creator that does not is enough to pair a primary with an attacker-made sidecar.
- **Positive identity beats negative exclusion.** A check that excludes a look-alike only because some other contract's input walk would fail is fragile. Prefer a positive check: exact commitment length, state prefix, or a pinned `lockingBytecode`.

## 5. Single-use credentials and uniqueness invariants

Some protocols create a one-time token to prove that a position was created correctly, for example an origin proof minted together with a position key. The invariant is "each proof backs exactly one position".

- Find every place the credential is accepted. If it is accepted by category and position only, find the output that consumes it. If no output pins it to `OP_RETURN`, and no free output is filtered to refuse it, the proof survives the transaction and can back a second position.
- A second position with the same identifier breaks every lookup by identifier: redemption, liquidation and interest settlement may act on the wrong one, or the two copies can be toggled so that neither can be liquidated.
- Public incident: ParyonUSD V1 (fixed 2026-10-08, block 972,003). The borrow path never required the origin proof to be destroyed, so a borrower could keep it and open a second loan with an existing loan's id. Settling a redemption against one copy left both loans unliquidatable, closable by no one and exempt from interest, a bad-debt risk if collateral prices fell. It was found by an AI-assisted review of the next version and confirmed by adding a single-use rule to the formal model, which then produced the exploit transaction unprompted. The fix filtered free outputs of the borrow transaction so that only capability-free tokens of the new loan's own category may leave it, which implicitly burns any proof.

## 6. Threaded state and fixes applied per thread

When a contract runs as several threads (several UTXOs with the same token), the spender chooses the thread. A defence placed in thread code protects nothing until **every** thread carries it; one thread left on old code reopens the hole. A fix delivered through migration must be verified thread by thread on chain.

## 7. Migration and privileged keys

Treat any key that can replace code or sign state as able to do everything that code or state allows. For each privileged role write: what it can change, whether consumers pin the new code or only the token, whether there is an on-chain notice period, and what users can do inside that period. Migrated code that keeps the authority token can do anything the token is trusted for, including acting as a function NFT or releasing a minting NFT, unless consumers check the script.

## 8. Formal and replay techniques that scale

- **Rebuild and diff.** Recompile every contract with the pinned compiler and options and compare against the shipped artifacts and their embedded sources.
- **Token-kind model.** Model the CashTokens validation rules as a finite tally over categories and capabilities, then check every transaction template against it. The trusted base is the consensus rule set, not the protocol's own templates.
- **Symbolic transaction search.** Let a solver choose the transaction shape (which contract at which index, which function, how many outputs) over the compiled bytecode, and prove an inductive policy: if inputs satisfy the system policy, outputs do too. Useful clauses: ownership of each privileged capability, function-NFT authenticity, sidecar adjacency, state shapes, and single use of one-time credentials.
- **Arithmetic invariants.** Use an SMT solver over unbounded integers with truncating division. Split nonlinear goals into lemmas. Bound every quantity that is later packed with `toPaddedBytes`, or the model will miss width overflows.
- **Replay every counterexample** on the real VM (the libauth BCH 2026 VM through the CashScript SDK), under both consensus and standardness rules, each with a negative control. Consensus and relay disagree in practice, for example a value that is valid but below dust.
- **Know the limits.** Hand-transcribed models drift from the code; single-position or single-period abstractions miss interactions; oracle behaviour, genesis, standardness and contention usually stay outside the model and must be reviewed by hand.
