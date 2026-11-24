# CashScript SDK, Build and Test Pitfalls (TypeScript)

The on-chain contract is only as sound as the artifact that was deployed, the constructor arguments it was given, and the tests that claim to cover it. These pitfalls come from reviewing CashScript 0.14 protocols, their `cashscript` / `@bitauth/libauth` test suites and their build scripts. Checkpoint `0x0016` in `SKILL.md` points here.

## P-01. Token ids passed in explorer byte order

```ts
// Vulnerable: category copied from a block explorer
const pool = new Contract(artifactPool, [poolTokenIdFromExplorer], { provider });

// Correct: the VM compares categories in OP_HASH256 (unreversed) order
const pool = new Contract(artifactPool, [reverseHex(poolTokenIdFromExplorer)], { provider });
```

Constructor arguments are never checked on chain. A wrong byte order produces a contract that authenticates a category that does not exist, so every function fails or, worse, a category an attacker can create matches. Check every token-id argument in deployment scripts and in `deployment-parameters` documents. Verify on chain that each deployed contract's locking bytecode matches the artifact compiled with the documented arguments.

## P-02. Locking-script arguments given as hashes

A `bytes` constructor argument compared with `tx.outputs[i].lockingBytecode` must be the full locking bytecode (`aa20<hash>87` for P2SH32, `76a914<hash>88ac` for P2PKH), not the hash. A hash compiles and deploys, then every payout check fails. Check the length of every such argument against the script type it claims.

## P-03. Compiler options silently disabled

The JS compile API with options passed as `undefined` disables the locktime guard and the parameter type checks (CashScript issue 461, open after 0.14.0). The artifact records the options it was built with. Confirm `compiler.options` in every artifact shows `enforceFunctionParameterTypes: true` and `enforceLocktimeGuard: true` when the design relies on them.

## P-04. Build scripts that swallow compile errors

A build script that logs a failed `cashc` run and continues leaves the previous artifact in place, so tests and deployment use stale bytecode. Rebuild every contract with the pinned compiler version and diff the result, and the embedded `source` and `debug.sources`, against the shipped artifacts.

## P-05. Tests on the wrong VM or with standardness off

The 2026 opcodes (`OP_DEFINE`, `OP_INVOKE`, `OP_BEGIN`, `OP_UNTIL`) run only on the `BCH_2026_05` VM. Tests must use it. A test that passes under consensus rules can still produce a transaction that will not relay (value below dust, unlocking bytecode over the standard limit). Verify critical transactions on the standard VM as well, and test the failing side: a value one satoshi below dust, a batch one item over the limit.

## P-06. Negative tests that pass for the wrong reason

```ts
// Weak: passes if ANY require with this substring fails, in any co-spent contract
expect(tx).toFailRequireWith('Invalid output');

// Strong: a project helper that traces the VM and reports which contract, line and input failed
expect(failingRequire(tx)).toEqual({ contract: 'Pool', line: 121, input: 0 });
```

Co-spent contracts often share identical `require` messages, and some messages are prefixes of others. A negative test can then pass because an unrelated check failed first, for example a price-thread pin that rejects the transaction before the check under test runs. Attribute failures by instruction pointer or by contract and line. Build each negative test from a passing transaction and change one thing.

## P-07. Coverage claims that do not hold

"Every require is covered" needs evidence. Measure by tracing VM execution per artifact frame: for each `require`, is there a test where it is the failing check? For each `if`, does some test take both branches? A claim of full coverage often falls short once measured this way. Typical gaps: optional-output branches (`if (tx.outputs.length > N)`), output pins pre-empted by another contract's check, and skipped version or sequence tests.

## P-08. Missing adversarial transaction shapes in tests

Tests usually build the intended transaction. Add shapes an attacker would build: an extra output carrying a minted NFT of each category the transaction can mint; the function at an unexpected index; two instances of one contract; a sibling function chosen through the selector; an older state UTXO or another thread; a credential reused in a second transaction. Each audit finding should become a behaviour test that fails today and passes after the fix.

## P-09. Flaky or slow verification

Verifying large padded batches on the standard VM takes seconds per transaction; default test timeouts make such tests flaky and invite people to skip them. Raise the timeout for those tests instead of removing them.

## P-10. Unpublished or unpinned dependencies

A test suite that depends on a contracts package that is not published, or on an unpinned compiler, cannot be reproduced. Pin `cashc`, `cashscript` and `@bitauth/libauth` from the lockfile and record the versions in the report.

## P-11. Off-chain builders and keepers

The transaction builder (dapp, keeper bot) chooses everything a contract leaves free: thread selection, free outputs, locktime, extra inputs. Review it as an untrusted party for safety, and as a trusted party for liveness. A keeper that skips positions in a certain state (for example pending redemptions) can create the lag that economic findings depend on.
