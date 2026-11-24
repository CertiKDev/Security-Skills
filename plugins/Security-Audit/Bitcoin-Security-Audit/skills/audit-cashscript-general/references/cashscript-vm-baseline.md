# CashScript, CashTokens and BCH VM Security Baseline

Language, compiler, VM and token-layer facts that a CashScript audit must apply line by line. Each item gives the rule, the usual failure, and a ripgrep pattern to run over the contracts. IDs `B-01` to `B-35` are referenced from the checkpoints in `SKILL.md`.

The facts reflect cashc 0.14.x and the BCH VM after the 2025-05-15 (BigInt, VM limits) and 2026-05-15 (functions, loops, P2S) upgrades. Re-check any item against the target's compiler version and the artifacts' ASM before relying on it. Sources are listed at the end as `[TAG]`.

## 0. Execution model in five rules

1. **State lives in UTXOs.** A contract instance is a UTXO locked by a P2SH32 script. Updating state means spending it and re-creating it at an output that the script pins: same locking bytecode, category with capability, commitment, value and token amount.
2. **Every input's script runs on its own.** There is no call stack, no return value and no shared memory. Each script sees the whole transaction read-only through introspection (`tx.inputs[i]`, `tx.outputs[i]`, `this.activeInputIndex`). The transaction is valid only if all input scripts pass and the token and value rules hold.
3. **Calling another contract means co-spending it.** A script authenticates its counterpart by token category and capability, NFT commitment, locking bytecode, or outpoint adjacency. Whatever a script does not check is attacker-chosen: extra inputs, extra outputs, foreign tokens on outputs, other protocol contracts in the same transaction, and index order.
4. **Tokens are conserved by consensus, not by scripts.** Fungible tokens cannot be created after genesis. NFTs are created only by a minting NFT, or one per mutable NFT. Tokens not carried to an output are burned.
5. **Time has only lower bounds.** `nLockTime` and `nSequence` let a script prove that at least height H has passed. No script can prove that H has not passed yet.

## A. CashTokens

**B-01. `tokenCategory` includes the capability byte.**
`tokenCategory` is empty when the output has no token, the bare 32-byte category for FT-only or an immutable NFT, and `category + 0x01` (mutable) or `category + 0x02` (minting) as 33 bytes. Categories are in VM byte order, the reverse of block explorers.
Failure: comparing to a bare id where a capability is required, or the reverse. `split(32)` on an empty category fails the script, which is an implicit "must carry a token" check. Constructor token ids passed in explorer byte order.
Grep: `rg -n "tokenCategory( ==|\.split\(32\))"`

**B-02. Empty NFTs are invisible.**
An immutable NFT with a zero-length commitment introspects exactly like an FT-only output: bare category plus empty commitment. `nftCommitment` is empty both without an NFT and with an empty one. `tokenAmount` is 0 without FT.
Consequence: to exclude FT, check `tokenAmount == 0`. To exclude junk NFTs, authenticate only on non-empty commitments. Whoever holds a minting NFT, or a free mutable budget, can attach an empty-commitment NFT to any output that is allowed to carry plain FT.
Grep: `rg -n "nftCommitment == 0x|tokenAmount == 0"`

**B-03. Capability powers are a per-category, per-transaction budget.** This is the most important item.
A minting input lets the transaction create any number of NFTs of its category, with any commitment and any capability, including new minting NFTs. Each mutable input lets the transaction create one NFT of its category, with any commitment, mutable or immutable. Immutable NFTs can only pass through unchanged or burn. Validation matches output immutables against input immutables first; each unmatched output NFT consumes one mutable input of that category unless a minting input is present.
Consequence: a spent mutable NFT that is not re-created at a pinned output leaves a free budget of one NFT that any unpinned output can receive. A spent minting NFT requires every output to be pinned or filtered for that category, and the output count to be bounded.
Grep: `rg -n "CAPABILITY_(MINTING|MUTABLE)|\+ 0x0[12]"`

**B-04. Fungible supply is fixed at genesis.**
After genesis, for each category the sum of output amounts is at most the sum of input amounts. Minting or mutable NFTs do not allow FT creation. Per-output amounts are 1 to 2^63-1.
Consequence: accounting only has to route tokens to the right outputs. A category created with FT at genesis breaks every "bare category means immutable NFT" assumption.
Grep: `rg -n "tokenAmount"`

**B-05. Genesis.**
A category id is the txid of an input spent at outpoint index 0. The spending transaction may create that category's tokens freely, including minting NFTs. Callers who can add inputs can always run a genesis of their own category in free outputs.
Failure: anything that authenticates "a category equal to some outpoint txid" without bounding the genesis outputs.
Grep: `rg -n "outpointIndex == 0|outpointTransactionHash"`

**B-06. Implicit and explicit burns.**
Tokens absent from outputs are destroyed. An `OP_RETURN` output burns explicitly. Both are valid.
Failure: a covenant meant to carry tokens forward does not pin them, so they can be dropped.
Grep: `rg -n "0x6a|NullData"`

**B-07. Outputs carry whatever is not forbidden.**
Each output carries zero or one category, with an optional NFT and optional FT of that category. An output whose category is not pinned can carry any token the transaction makes available. A BCH-only output is `tokenCategory == 0x`. An NFT-only output is category plus commitment plus `tokenAmount == 0`.
Grep: `rg -n "tokenCategory == 0x"`

**B-08. Commitments are up to 128 bytes since 2026-05-15 (40 before).**
Reads are free. Failures happen only when a `split` or `slice` index exceeds the length (B-23), and `unsafe_bytesN` adds no check (B-22). "At most 40 bytes, so this field cannot exist" is no longer true.
Grep: `rg -n "nftCommitment"`

**B-09. Dust includes the token prefix.**
Relay dust is `3 x (serialized_output_size + 148)` sats at the default fee rate. The serialized size includes the token prefix (1 + 32 + 1 + commitment length + commitment + FT amount) and the locking bytecode. `OP_RETURN` outputs are exempt. Worked numbers: P2SH32 with a mutable NFT of L bytes and no FT has dust `681 + 3L`, so a fixed 1,000-sat value becomes non-standard at L >= 107. An FT-only output with an L-byte locking script needs at most 1,000 sats only when L <= 133.
Failure: a covenant that pins a fixed value on an output whose script or commitment can grow. This is liveness (B-30), unless every path is affected.
Grep: `rg -n "value (==|>=)|DUST"`

## B. Introspection, indices and composition

**B-10. `this.activeInputIndex`.**
Each input's script runs separately. A function that neither pins its own index nor derives every other index from it can be satisfied at an unexpected position, or by two instances of the same contract in one transaction that both check the same counterpart.
Grep: `rg -n "activeInputIndex"`

**B-11. Index validity and non-short-circuit booleans.**
Introspection with an out-of-range index fails the script (fail-closed). CashScript `&&` and `||` evaluate both sides, so an out-of-range read on the "unused" side still fails.
Grep: `rg -n "&&|\|\|"`

**B-12. Sidecar pairing by outpoint adjacency.**
`in[a].outpointTransactionHash == in[b].outpointTransactionHash && in[a].outpointIndex == in[b].outpointIndex + 1` proves only that both UTXOs were created by one transaction at consecutive indices. It is sound only if every transaction that creates or re-creates the primary UTXO also pins its sidecar at the adjacent index with the expected token. That is an induction over every creator.
Grep: `rg -n "outpointIndex"`

**B-13. Locking bytecode forms.**
P2SH32 is `aa20 <32-byte hash256(redeem)> 87` (35 bytes), P2SH20 is 23 bytes, P2PKH is 25 bytes. Since 2026 any bare script of at most 201 bytes is a standard output (P2S). `out.lockingBytecode == in.lockingBytecode` binds code and constructor arguments together. `OP_ACTIVEBYTECODE` inside an invoked function returns the function body.
Grep: `rg -n "lockingBytecode|LockingBytecodeP2"`

**B-14. Unbounded input and output counts; double satisfaction.**
Unpinned outputs and extra inputs are attacker-chosen. Without an output bound, a transaction that spends a minting NFT or leaves a mutable budget free can mint into extra outputs. Even with every category pinned, two covenants may each be satisfied by the same output or input, for example two scripts that each require "an output paying X to Y" when one output pays X once.
Grep: `rg -n "tx\.(outputs|inputs)\.length"`

**B-15. Token authentication versus bytecode authentication.**
Authenticating by category, capability and commitment trusts everything that can create that token (B-03, B-05). Authenticating by `lockingBytecode` trusts the script and its constructor arguments, but not the state in the token. A design that authenticates function contracts by token alone rests on genesis distribution and mint containment.
Grep: `rg -n "lockingBytecode == [a-zA-Z]+|LockingBytecodeP2SH32\("`

## C. Numbers

**B-16. `int(bytes)` is `OP_BIN2NUM` and is signed.**
VM numbers are little-endian sign-magnitude. `int(bytes)` accepts any byte string: `0x...80` becomes 0, and a set top bit yields a negative number. `int` function parameters get no compiler check; non-minimal encodings fail at their first numeric use.
Grep: `rg -n "int\("`

**B-17. BigInt: no overflow since 2025-05-15.**
Numbers are bounded only by the 10,000-byte stack element. `rate * debt * periods` computes exactly. "This would overflow and fail" is no longer a defence. The remaining implicit bounds are `toPaddedBytes` width (B-19), `tokenAmount <= 2^63-1` and the money range of `value`.
Grep: `rg -n "\*" --glob '*.cash'`

**B-18. Division and modulo.**
`/` truncates toward zero, `>>` floors, `%` takes the dividend's sign. Division or modulo by any zero fails the script.
Failure: divisors from state or constructor that can reach 0 (a brick), rounding that favours the caller, and two contracts computing "the same" quantity with different expressions that differ by one unit.
Grep: `rg -n " / |%"`

**B-19. `toPaddedBytes(x, n)` and `bytes(int)`.**
`toPaddedBytes` is `<n> OP_NUM2BIN` and fails when `x` needs more than `n` bytes (|x| <= 2^31-1 for n = 4, 2^63-1 for n = 8). A negative `x` encodes with the sign bit set and succeeds; the next reader decodes it as negative. `bytes(int)` emits no opcode and yields the minimal encoding: 0 becomes empty and values with the top bit set gain a byte, so the length varies.
Grep: `rg -n "toPaddedBytes|bytes\("`

**B-20. Unsigned protocol fields land in signed state.**
`tx.locktime` and sequence numbers are positive VM numbers up to 5 bytes. Writing them into a 4-byte signed field needs the value below 2^31.
Grep: `rg -n "toPaddedBytes\(tx\.|sequenceNumber"`

**B-21. Byte equality versus numeric equality.**
`==` on `bytes` is `OP_EQUAL` (exact bytes); on `int` it is `OP_NUMEQUAL`. `0x0100` and `0x01`, or `0x00000000` and `0x`, are unequal as bytes. Byte comparisons of numeric fields are safe only if every writer, genesis included, uses one fixed-width encoding.
Grep: `rg -n "Bytes ==|== [a-z]+Bytes"`

## D. Bytes and layouts

**B-22. `unsafe_bytesN` checks nothing; lengths hold only by induction.**
`unsafe_bytesN(x)` emits no opcode. `split(k)` remainders keep the real length, so a longer commitment yields longer fields. A writer that rebuilds state from remainders is length-preserving and never repairs a bad length. A writer built only from fixed `slice` and `toPaddedBytes` pieces is normalizing. Layout safety is an induction from the genesis lengths over every writer.
Grep: `rg -n "unsafe_bytes"`

**B-23. `split` and `slice` bounds.**
`OP_SPLIT` fails if the position is negative or greater than the length; `split(len)` succeeds with an empty right part. cashc compiles `slice(a,b)` to `<b> OP_SPLIT OP_DROP <a> OP_SPLIT OP_NIP`, which fails when `b > len`. A too-short commitment fails closed. cashc 0.14.0 fixed a `slice(v, v+1)` miscompile when one variable appears in both arguments.
Grep: `rg -n "\.split\(|\.slice\("`

**B-24. Variable-length fields.**
A variable-length field is unambiguous only if it is last and every reader uses the same offset. Branching on a length (`x.length == 32`) is safe only if the writer restricted the lengths.

## E. Time

**B-25. `tx.time` versus `tx.locktime`.**
`require(tx.time >= x)` compiles to CLTV. `tx.locktime` is the raw `nLockTime` with no enforcement. CLTV fails if the operand is negative, if operand and `nLockTime` are on different sides of 500,000,000, if the operand exceeds `nLockTime`, or if the executing input's sequence is `0xFFFFFFFF`. With `enforceLocktimeGuard` (cashc 0.13+), the compiler injects `require(tx.time >= tx.locktime)` into functions that read `tx.locktime`. The guard proves only that the executing input is non-final; the 500M boundary must be checked by hand. `tx.locktime` is chosen by the spender and may be any past value.
Grep: `rg -n "tx\.locktime|tx\.time"`

**B-26. `this.age` versus `sequenceNumber`.**
`require(this.age >= x)` is CSV on the active input only. CSV needs tx version 2, bit 31 clear, matching type bit 22, and the low 16 bits large enough. Checking another input's relative lock needs `sequenceNumber` introspection with exact equality plus `tx.version == 2`, because extra bits pass a `>=` test while changing or disabling BIP68. An open cashc issue encodes `this.age` with time units as blocks.
Grep: `rg -n "this\.age|sequenceNumber|tx\.version"`

## F. VM limits

**B-27. Operation cost and other limits.**
The per-input budget is `(41 + unlockingBytecodeLength) x 800`; the unlocking bytecode of a P2SH input includes the redeem script and every argument. Each instruction costs 100, including unexecuted ones and pushes, plus pushed bytes; arithmetic adds result size and `|a| x |b|` for multiply and divide; each hash iteration adds 192; each signature check adds 26,000. The control stack holds 100 entries shared by `if`, function frames and loops. Stack, altstack and defined functions together hold 1,000 items. Loops pay the whole body on every iteration. Unused padding parameters buy 800 budget per byte.
Grep: `rg -n "while|for ?\(|do \{|unused"`

**B-28. The 2026 opcodes are a deployment dependency.**
`OP_BEGIN`/`OP_UNTIL` and `OP_DEFINE`/`OP_INVOKE` activated on mainnet at MTP 1778846400 (2026-05-15). cashc 0.13+ targets VM `BCH_2026_05`; tests must run on that VM.
Grep (artifacts): `rg -o "OP_(DEFINE|INVOKE|BEGIN|UNTIL)" artifacts | sort | uniq -c`

**B-29. Never rely on a limit failing.**
The limits CHIPs treat constructions that rely on exceeding a limit as intentional and allow future upgrades to raise limits. Only explicit checks count. `OP_NUM2BIN` width is an explicit consensus rule and is acceptable.

## G. Standardness and state races

**B-30. Relay rules are not consensus.**
Standard transactions: version 1 or 2, at most 100,000 bytes, push-only unlocking bytecode of at most 10,000 bytes (1,650 before 2026-05-15), standard outputs (P2S or a known template), at most 223 bytes of cumulative `OP_RETURN` locking script, no dust outside `OP_RETURN`. Token-carrying `OP_RETURN` burns are standard. A non-standard transaction can still be mined, so standardness costs liveness only. A covenant is bricked only when every spend path is consensus-invalid: a state that fails every function, a counter at its width limit, a divisor at zero.

**B-31. Stale state and threads.**
Anyone can build on an older unspent state UTXO or race a pending transaction. With threaded state (several UTXOs of one contract), the spender chooses the thread, which for a price means choosing the price. Singletons serialize users, so contention is a liveness issue.

## H. Signatures

**B-32. `checkDataSig` and `checkSig`.**
`checkDataSig(sig, msg, pk)` verifies a signature over `SHA256(msg)`. There is no domain separation, nonce or expiry beyond the signed bytes, so any published message can be replayed subject to the contract's own freshness checks. `datasig` parameters get no compiler size check. Where authority is token possession rather than signatures, wallet sighash choices only affect which token-holding UTXOs a third party can co-spend.
Grep: `rg -n "checkDataSig|checkSig|datasig"`

## I. Compiler and build

**B-33. What cashc injects and drops.**
Injected: `OP_SIZE <n> OP_EQUALVERIFY` for `bytesN`, `byte` and `bool` parameters at the start of each function branch (`enforceFunctionParameterTypes`); the locktime guard (B-25); a selector where each function is `OP_PICK <k> OP_NUMEQUAL OP_IF` and the last is `OP_NUMEQUALVERIFY`, so an unknown selector fails.
Not checked: `int`, unsized `bytes`, `datasig`, `sig` and `pubkey` function parameters; `unused` parameters (dropped at once). `require` messages are debug-only. `&&` and `||` do not short-circuit. Global functions and constants are inlined or shared through `OP_DEFINE`/`OP_INVOKE`.
Grep: `rg -n "function [a-zA-Z]+\("`

**B-34. Compiler maturity.**
cashc 0.14.0 introduced user functions, global constants, imports and `unused`. Fixed before release: a `for`-init reassignment miscompile, the `slice(v, v+1)` miscompile, and `LockingBytecodeNullData` chunks over 255 bytes. Open after 0.14.0: compiler options passed as `undefined` silently disable the guard and parameter checks (JS API), `this.age` time units encoded as blocks, `debug()` misattributing failures inside invoked functions. A compiler release younger than the audit window is itself a risk factor for its new code generation.
Grep: `rg -n "for ?\(|slice\(|this\.age|LockingBytecodeNullData"`

**B-35. Artifacts and constructor arguments.**
Artifacts embed `source` and `debug.sources` and the compiler options; compare them byte for byte with the repository. Constructor arguments are not checked on chain: a `bytes` locking-script argument must be the full locking bytecode, not a hash, and token ids must be in VM byte order. A build script that logs a failed compile and continues can leave a stale artifact.
Grep: `rg -n "^contract|bytes[0-9]* [a-zA-Z]+,?$"`

## Per-function review card

Apply to every function, after the transaction-shape map exists.

1. Selector: is the function safe if the spender picks it in a transaction meant for a sibling? (B-33)
2. Own index pinned, or every other index derived from it? Can two instances coexist? (B-10)
3. Every `tx.inputs[i]` read: what authenticates it? (B-01, B-12, B-15)
4. Does a bare-category check also admit FT-only or empty-commitment junk? (B-02, B-04)
5. Every minting or mutable input of every category in this transaction shape: re-created at a pinned output? (B-03)
6. Every output: bytecode, category with capability, commitment, amount and value pinned? If free, what can it carry? (B-07)
7. Output count bounded? If not, which script in the transaction bounds it? (B-14)
8. Could one output or input satisfy two scripts at once? (B-14)
9. Every `int(...)`: negative or longer than expected? (B-16, B-22)
10. Every subtraction written to state: `>= 0` checked or proven? (B-19)
11. Every `/` and `%`: divisor positive? Rounding favours whom? Same expression elsewhere? (B-18)
12. Every `toPaddedBytes(x, n)`: can `x` exceed the width or be negative? (B-19)
13. Every `bytes(x)`: field last? Does `x = 0` give an empty field that readers accept? (B-19, B-24)
14. Every `unsafe_bytesN` or `split` remainder: normalizing or length-preserving writer? (B-22)
15. Byte `==` on numeric fields: same encoding at every writer? (B-21)
16. `tx.locktime`: guard present in ASM, 500M boundary checked, backdating harmless? (B-25)
17. Relative locks: `this.age`, or exact `sequenceNumber ==` plus `tx.version == 2`; value in 1..65535? (B-26)
18. Loops: cost per iteration times maximum iterations within budget? (B-27)
19. Output values at least dust for the real serialized size? (B-09)
20. Can any state make every path fail? (B-30)
21. Oracle reads: which thread, how stale, who chooses? (B-31, B-32)
22. Constructor arguments: format, length, byte order? (B-35)
23. Compiler-dependent behaviour confirmed in the artifact ASM? (B-33, B-34)

## Sources

- [CT] CHIP-2022-02 CashTokens: https://github.com/cashtokens/cashtokens
- [P2S] CHIP-2024-12 P2S (128-byte commitments, 10,000-byte unlocking bytecode, 201-byte standard outputs): https://github.com/bitjson/bch-p2s
- [LIM] CHIP-2021-05 VM Limits: https://github.com/bitjson/bch-vm-limits
- [BIG] CHIP-2024-07 BigInt: https://github.com/bitjson/bch-bigint
- [LOOP] CHIP-2021-05 Loops: https://github.com/bitjson/bch-loops
- [FN] CHIP-2025-05 Functions: https://github.com/bitjson/bch-functions
- [UPG26] BCHN 2026-05-15 upgrade: https://upgradespecs.bitcoincashnode.org/2026-05-15-upgrade/
- [INTRO] CHIP-2021-02 Native Introspection: https://gitlab.com/GeneralProtocols/research/chips/-/blob/master/CHIP-2021-02-Add-Native-Introspection-Opcodes.md
- [OPS2018] Re-enabled opcodes (OP_SPLIT, OP_DIV, OP_NUM2BIN, OP_BIN2NUM): https://upgradespecs.bitcoincashnode.org/may-2018-reenabled-opcodes/
- [MINDATA] Minimal number encoding: https://upgradespecs.bitcoincashnode.org/2019-11-15-minimaldata/
- [DSIG] OP_CHECKDATASIG: https://upgradespecs.bitcoincashnode.org/op_checkdatasig/
- [BIP65], [BIP68], [BIP112], [BIP113]: https://github.com/bitcoin/bips
- [POLICY] BCHN `src/policy/policy.cpp` (`GetDustThreshold`, `IsStandardTx`): https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/master/src/policy/policy.cpp
- [CS] CashScript docs (language, compiler, CashTokens gotchas, script limits, adversarial analysis, release notes): https://cashscript.org/docs
- [CS-GH] CashScript PRs and issues 455, 459, 461, 464, 466, 475: https://github.com/CashScript/cashscript
