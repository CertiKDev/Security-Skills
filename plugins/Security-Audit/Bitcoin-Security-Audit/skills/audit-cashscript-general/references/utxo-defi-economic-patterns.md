# Economic and Liveness Patterns in UTXO DeFi on Bitcoin Cash

Patterns behind confirmed findings in production CashScript DeFi audits, plus public incidents. Each entry gives the shape, why the UTXO model produces it, how to quantify it, and which fixes are enforceable. Checkpoints `0x000a` to `0x0015` in `SKILL.md` point here.

The common root: a script can only check the transaction in front of it. It cannot read another contract without spending it, cannot prove that time has not passed, and cannot mint fungible tokens after genesis. Every pattern below follows from one of those limits.

## E-01. The spender chooses which oracle thread, and therefore which price

**Shape.** Price state lives in several UTXOs (threads) so that many users can read it at once. Consumers authenticate a price UTXO by category, capability and a state byte. Each thread orders its own messages by sequence number, but nothing orders threads against each other, and the message timestamp is not stored or checked.
**Effect.** A borrower, liquidator or redeemer picks the thread whose price suits them: the stalest one after a drop or a rise. Positions can be opened, modified or redeemed at a price that the oracle has already superseded.
**Quantify.** The maximum gap between threads equals the largest price move inside the slowest thread's update interval. Compute the gain for each consumer (extra debt at open, avoided liquidation, redemption over-extraction) at realistic moves and state the move at which harm starts.
**Fixes that work.** Store the oracle timestamp or a global sequence in state and require it within a bound of a value that only moves forward; publish every message to every thread in one transaction; let consumers require the freshest of several threads. A fix that only tightens per-thread ordering changes nothing, and "consumers must use the latest message" cannot be enforced because no script knows which message is latest.

## E-02. No circuit breaker for a stale oracle

**Shape.** Consumers accept any authenticated price, however old. A script cannot prove "the oracle is late", because it cannot prove that a height has not been reached yet.
**Effect.** During an oracle outage the last price stays usable indefinitely. Borrowers open or withdraw against a price above market; liquidations stop when the real price falls.
**Quantify.** Break-even price move for opening a loan at the stale price and walking away, and the time to reach that move at realistic volatility.
**Fixes that work.** A latch based on what can be proven: anyone may mark a thread stale with a transaction whose `tx.locktime` is past `lastUpdateHeight + window`, and consumers refuse stale threads until a fresh message clears the flag. Check that the flag does not block the migration escape and that every parser of the state layout is updated. A rule that the update must happen "in the same transaction as every consumer" serializes all users through one UTXO and is not workable.

## E-03. Privileged signers and migration keys control everything downstream

**Shape.** An oracle key signs prices and a migration key can replace price-contract code. Consumers authenticate the price thread by token only, not by script.
**Effect.** The signer can publish any price without notice; the migration key can install code that keeps the authority token and therefore does anything the token is trusted for. Reach is all collateral and any reserve that depends on price. In one public incident the migration path was also the delivery channel for a fix, which shows how much it can change.
**Quantify.** List what each key can do in one transaction, whether users get an on-chain notice period, and whether borrowers (not only liquidity providers) can exit inside it.
**Fixes that work.** An on-chain announcement with a notice period measured by a relative timelock; restricting migrated code to a published set or pinning the consumer-side check to the script; price-move bounds per message; a multisig or threshold signer. Report it as a centralization finding whose severity follows from the reach.

## E-04. Fixed fungible supply split across reserve threads

**Shape.** The stablecoin supply is minted at genesis and held as FT in several reserve UTXOs. Borrowing, draws and interest release tokens; repayments and liquidations burn to `OP_RETURN` instead of returning them. A mandatory settlement must release a whole amount from exactly one thread at one index.
**Effect.** Once every thread holds less than the amount due, no valid settlement exists and the period clock stops. Deposits made during the stuck period cannot be withdrawn, interest stops, and borrowing ends at exhaustion. Anyone can push a thread down by borrowing and repaying in a cycle, paying only the borrowing fee. Variants: an accumulated tally that grows past the reserve through ordinary accrual or a surcharge hand-off; a zero-stake roll that carries the tally forward and leaves the deficit for the next staked period.
**Quantify.** Lifetime gross issuance (borrowing, draws, all interest and surcharges) against the genesis supply; the cost to drain each thread deliberately; the per-period tally.
**Fixes that work.** Let settlement source from more than one thread or add a merge function; return repaid tokens to a reserve thread; size the supply far above lifetime issuance and document the liveness condition. "Reserve liquidity for the tally before every borrow" needs the tally holder in every borrow, which serializes all borrowing through one UTXO.

## E-05. Rounding residue blocks a zero-check branch

**Shape.** A total is built from per-position values with floor division (for example each position's share after a loss), and a branch is chosen when the total is exactly zero (for example "nothing staked, roll the period without settlement").
**Effect.** After every position exits, a residue of a few base units keeps the total positive. The zero branch never runs; the other branch needs funds or participants that no longer exist, so the system stalls. A mirror case: a position scaled to exactly zero by a loss cannot exit because its exit divides by the zero total.
**Quantify.** Maximum residue per operation (usually n − 1 base units for n positions) and which sequence of operations reaches the stall.
**Fixes that work.** Choose the branch on "no live positions" rather than on an amount; sweep residue below a threshold; guard every division by the total. Check that the fix does not strand positions that losses shrank below the threshold, and does not reintroduce the divide-by-zero.

## E-06. A permissionless function restarts a relative timelock

**Shape.** A position must wait `this.age >= T` (or an exact sequence number) before settlement. Another function that anyone can call re-creates the same UTXO (a swap, a re-target, a top-up), and every re-creation restarts its age.
**Effect.** A third party, or the position holder, can postpone settlement indefinitely or hold an option on price movement while the counterparty is locked. In a redemption system this lets the redeemer delay settlement until the price favours them. Ordering rules that allow only moves to a "strictly better" target do not stop it: the attacker prepares a descending ladder of their own small positions, or uses a permissionless state refresh to make a prepared position eligible after the claim started, then parks the claim on their own positions and moves it onto the victim only when the price is favourable. "Anyone can settle" does not help when the attacker holds both sides or the victim is passive. Even without moves, a locked price plus the right to cancel at a later boundary is an option.
**Quantify.** Value of the option as a function of volatility and the reset interval (a Monte Carlo over geometric Brownian motion is enough), for the passive and the laddered strategy; compare against any documented bound.
**Fixes that work.** Record the start height in state and measure the wait from it with `tx.locktime` (a lower bound is what is needed here); re-lock the price at each swap if price is the issue; restrict who can re-create the UTXO. Verify the new field does not break other readers' offsets.

## E-07. Charges accrue only when someone reports them

**Shape.** Interest or fees are charged by a keeper function per elapsed period. Functions that reduce or remove a position (repay, close, liquidate, redeem, withdraw collateral) use the recorded amount and do not require the position to be current.
**Effect.** An exit forgives every unreported period. Liquidation eligibility and collateral-withdrawal margins are evaluated against an understated debt. Pending operations that freeze the reporting marker widen the gap. A repay-report-redraw cycle can be profitable when the rate is high relative to the borrowing fee.
**Quantify.** Forgiven amount per exit with a timely keeper (usually at most one period) and with lag; the rate at which the cycle pays (`rate × periods > fee`); the true collateral ratio after a withdrawal, `margin / (1 + rate × k)`.
**Fixes that work.** Compute outstanding charges inside each debt-reducing function and include them in the burn and the eligibility test; or require the marker to be current, which needs the period holder in every such transaction (contention, and no read-only inputs exist); or a maximum rate below the fee. Note that a fix based on "elapsed time" can be gamed by setting an early `tx.locktime`.

## E-08. Period clocks advance by lower-bound locktime only

**Shape.** A period-advance function requires `tx.locktime >= boundary(next period)` and moves the clock by one. Positions created now are dated "next period".
**Effect.** After a lag, all catch-up steps can run in one block. Capital deposited during the lag is counted in every catch-up period and shares rewards that accrued while others carried the risk, with almost no exposure itself. State copied from a stale thread (a borrowing thread whose period was not updated) backdates new positions in the same way.
**Quantify.** Gain bounded by (lag − 1) periods of rewards times the newcomer's share; state whether the attacker can create the lag (usually not).
**Fixes that work.** A relative timelock between consecutive advances so each period carries real exposure, accepting slower catch-up after an outage; or document the behaviour and commit to running the advance every period. "Reject deposits while the pool is behind" is not enforceable, because no script can prove the current height is below a boundary.

## E-09. Leftover value and unsigned outputs

**Shape.** Covenant-only transactions (no signed input) or flows where BCH is not fully pinned.
**Effect.** Unpinned value goes to whoever builds the transaction; an unpinned output in an unsigned transaction can be redirected by a miner; an unread unlocking argument (dropped by `unused`, no length check) makes the txid malleable and breaks chained batches.
**Fixes that work.** Pin keeper rewards and change explicitly; give unread padding a fixed size; document which outputs are the builder's.

## E-10. Fixed BCH deductions without a floor; values below dust

**Shape.** A function deducts a fixed fee or allowance from a UTXO's value without a minimum, or pins a fixed value on an output whose script or commitment can grow.
**Effect.** After enough deductions the output is below dust: consensus-valid but non-standard, so the operation stops relaying. If the value can go negative, every path fails.
**Quantify.** Number of operations to reach dust for the real serialized size (token prefix included).

## E-11. Contention on shared UTXOs

**Shape.** A shared UTXO (oracle thread, pool, collector) has a function that anyone can call at any index without needing a consumer, such as a read or share function.
**Effect.** First-seen relay lets a spammer keep spending the UTXO and delay honest updates. Under first-seen relay a well-connected keeper usually lands within a few blocks, so the realistic effect is delay, not permanent blocking.
**Quantify.** State the network assumption explicitly; a live test on the real network settles whether blocking is sustained.

## E-12. Single-use credentials that survive (public incident)

See `authority-containment-method.md` section 5. The ParyonUSD V1 borrow path accepted an origin proof by category and position, never required its destruction, and so allowed two loans with one identifier; both could be made unliquidatable. Fixed on 2026-10-08 by migrating every price thread to code that filters the borrow's free outputs.

## Other public lessons from the same incident report

- **Locktime enforcement.** Consensus enforces `nLockTime` only if at least one input is non-final, so a transaction with all-final inputs makes `tx.locktime` an unenforced number. The original guard checked a fixed input's sequence number by hand; the fix replaced it with a `require(tx.time >= 0)` prologue, which compiles to CLTV and makes the executing input itself prove non-finality.
- **Mutable NFT re-emerging on close.** A close path that consumed a position's mutable NFT without an explicit category-pinned burn let it re-appear on a user-controlled output.
- **Oracle message hardening.** Exact message length and `price > 0` checks, so short, long, zero or sign-bit prices cannot reach consumers.
- **Fee direction.** A redemption price multiplier was in the wrong direction (995/1000 instead of 1005/1000). Check the sign of every fee against the documented intent.

## Quantification habits

- State every assumption (supply, rate, volatility, keeper behaviour) next to the number, and give the threshold at which severity changes.
- Ask the counterfactual: would the harm have happened anyway with an honest oracle or a timely keeper? Several first-draft severities fell once this was asked.
- Recompute every figure with a script and keep it with the finding.
- Distinguish "the attacker can cause this" from "this happens if operators lag"; the second is usually Minor unless the lag is cheap to create.
