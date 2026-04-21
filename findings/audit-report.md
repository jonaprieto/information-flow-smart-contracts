# Security Audit Report — SCIF Information Flow Models

**Scope**: All SCIF models in `information-flow-smart-contracts/` versus ground-truth Solidity in `anomapay-erc20-forwarder/` and `pa/`.
**Auditor focus**: Fund loss, double-spend, confused deputy attacks, reentrancy, authorization gaps, V3 constructor bug impact.

---

## Critical / High Severity

### CRIT-1: Emergency Committee Is a Single Point of Unconditional Fund Drain

> **Severity note**: This finding describes the designed governance model, not an unintended vulnerability. The emergency committee IS the intended root of trust for the recovery path. Severity depends on whether the committee is a multisig with adequate operational security. If the committee is a single EOA, this is Critical. If it is a well-configured multisig with time-lock, the on-chain risk is lower (but the contract itself provides no such guarantees).

**Attack scenario**: The `_EMERGENCY_COMMITTEE` address (immutable, set at deploy time) calls `setEmergencyCaller(attackerAddr)` once PA is stopped. Attacker immediately calls `forwardEmergencyCall(input)` with `callType = Unwrap` and drains the full token balance of the forwarder in one transaction. No time-lock, no multisig threshold within the contract, no rate limit.

**Affected contract**:
- Solidity: `EmergencyMigratableForwarderBase.sol:55-68` (`setEmergencyCaller`) and `42-52` (`forwardEmergencyCall`)
- SCIF: `EmergencyMigratableBase.scif:129-164` and `188-224`

**Root cause**: The entire emergency drain capability is a one-step, single-actor privilege escalation. The label chain `_EMERGENCY_COMMITTEE ({this}) → _emergencyCaller ({this}) → drain` has no intermediate endorser. SCIF's type system surfaces this: `endorse(newEmergencyCaller, sender -> this)` at line 163 of `EmergencyMigratableBase.scif` is justified solely by the single runtime check `sender == _EMERGENCY_COMMITTEE`. There is no on-chain multi-approval requirement.

**Mitigation**: Add a time-lock between `setEmergencyCaller` and the first permitted `forwardEmergencyCall`. Alternatively require a multi-sig confirmation with a delay. The SCIF model would need a second endorser principal to represent this.

---

### HIGH-1: ZK Circuit Gaps Make All PA Endorsements Unsound by Default

**Attack scenario**: PA's `execute` function endorses 9 calldata fields to `{this}` integrity after `_processRiscZeroProof` returns without reverting. If the ZK circuit (RISC Zero guest program) does not bind a specific field — for example, the `forwarderAddr` or the `receiver` address in an unwrap operation — then the `endorse(forwarderAddr, sender -> this)` in `ProtocolAdapterCore.scif:92` is semantically unsound: the attacker controls that field despite the PA treating it as trusted. In ERC20Forwarder, the `receiver` in an unwrap is similarly endorsed (line 156) with the same dependency on the ZK circuit.

**Affected contract**:
- Solidity: `ProtocolAdapter.sol:320-336` (`_executeForwarderCall`) — forwarder address decoded from `callBlob` without per-field validation
- SCIF: `ProtocolAdapterCore.scif:89-94` — all 6 endorsements after proof verify, `ERC20Forwarder.scif:147-156` — all 10 endorsements

**Root cause**: SCIF makes explicit what Solidity hides: there are exactly 16 endorsement sites whose soundness is entirely determined by the ZK circuit's coverage. SCIF cannot verify the RISC Zero guest. This is documented in the model as an oracle assumption, but the practical implication is that a circuit bug (e.g., a missing `receiver` constraint) silently breaks the entire forwarder's access control.

**Mitigation**: Audit each of the 16 endorsed fields against the RISC Zero guest program's journal to confirm every endorsed field appears as a constrained public input. This is the highest-leverage action enabled by the SCIF analysis.

---

### HIGH-2: Confused Deputy Attack via User-Controlled Forwarder Address

**Attack scenario**: A user constructs a transaction where the `externalPayload.blob` contains a forwarder address that points to a malicious contract. PA calls `IForwarder(untrustedForwarder).forwardCall(logicRef, input)` with `msg.sender == PA`. The malicious contract passes `msg.sender == _PROTOCOL_ADAPTER` and executes arbitrary logic with PA's authority. This is the Dexible CDA pattern applied to this architecture.

**Affected contract**:
- Solidity: `ProtocolAdapter.sol:320-326` — `untrustedForwarder` decoded from calldata, no allowlist check on-chain
- SCIF: `ProtocolAdapterCore.scif:92` — `address{this} eForwarder = endorse(forwarderAddr, sender -> this)` with comment explicitly flagging this as CDA risk

**Root cause**: The forwarder address has `{sender}` label before endorsement. After endorsement, it acquires `{this}` integrity — but the justification is the ZK proof, which is an oracle (see HIGH-1). If the ZK circuit permits arbitrary forwarder addresses, an attacker can direct PA to call any contract as a trusted deputy.

**Mitigation**: Maintain a registry of approved forwarder addresses in the PA with on-chain verification, or ensure the ZK circuit constrains `forwarderAddr` to a fixed set of known forwarder addresses at proof generation time.

---

## Medium Severity

### MED-1: Write-Once Invariant of `_emergencyCaller` Is Runtime-Only — Not Label-Enforced

**Attack scenario**: Any future contract upgrade that removes or bypasses the `if (_emergencyCaller != address(0)) revert EmergencyCallerAlreadySet(...)` guard at `EmergencyMigratableForwarderBase.sol:62-63` would allow the committee to replace the emergency caller silently, effectively transferring drain authority to a new address after the original emergency caller has already started migration. The SCIF type system labels `_emergencyCaller` as `{this}` (only the contract can write it), but `{this}` integrity does not constrain write frequency.

**Affected contract**:
- Solidity: `EmergencyMigratableForwarderBase.sol:62-63`
- SCIF: `EmergencyMigratableBase.scif:144-148` — documented as "RUNTIME ONLY (not a label property)"

**Root cause**: SCIF has no "write-once" principal or label. The protection is a single storage check that can be removed by a future upgrade without any type-system warning.

**Mitigation**: Consider using an immutable-equivalent pattern: once set, never expose a setter. Or use a proxy pattern with a locked migration slot. Document in the SCIF model that this guard must not be removed.

---

### MED-2: Cross-Contract Emergency Call Chain Requires Implicit Deployment-Time Invariant

**Attack scenario**: V3's `_migrateV1` calls `_ERC20_FORWARDER_V2.forwardEmergencyCall(...)` twice. For these calls to succeed, V3's contract address must be V2's registered `_emergencyCaller`. This deployment constraint is never verified anywhere in V3's constructor or in the SCIF model. If V2's `_emergencyCaller` is set to a different address (or not set), all V1-resource migrations via V3 will revert at the `_checkCaller(_emergencyCaller)` step in V2 — permanently blocking V1 migration via V3.

**Affected contract**:
- Solidity: `ERC20ForwarderV3.sol:133-143` — two `forwardEmergencyCall` calls on V2, no check that V3 == V2's `_emergencyCaller`
- SCIF: `ERC20ForwarderV3.scif:227-233` — noted as "oracle assumption" in Finding 10

**Root cause**: The two-level call chain `V3 → V2.forwardEmergencyCall → V1.forwardEmergencyCall` requires a three-contract trust setup that is not verifiable on-chain at construction time. SCIF surfaces this as an implicit endorsement chain but cannot enforce the deployment constraint.

**Mitigation**: Add a constructor check: `require(V2._emergencyCaller == address(this) || V2._emergencyCaller == address(0))`. If `_emergencyCaller` is already set on V2 to something other than V3, revert deployment.

---

### MED-3: SCIF Model Checks Wrong PA for V3 Emergency Stop Condition — FIXED

> **Status**: Fixed in `ERC20ForwarderV3.scif`. The model now stores `_PROTOCOL_ADAPTER_V3` and uses it for both `setEmergencyCaller` and `forwardEmergencyCall` emergency stop checks.

**Original issue**: The model called `IProtocolAdapterEmergencyCheck(_PROTOCOL_ADAPTER_V2).isEmergencyStopped()` instead of V3's own PA. In the real Solidity, `_checkEmergencyStopped` uses `_PROTOCOL_ADAPTER` (which ForwarderBase sets to `protocolAdapterV3`). If V2 was stopped but V3's PA was still running, the SCIF model would admit the emergency call while the real contract would reject it.

**Affected contract**:
- Solidity: `EmergencyMigratableForwarderBase.sol:86-90` — `_checkEmergencyStopped` uses inherited `_PROTOCOL_ADAPTER`
- SCIF: `ERC20ForwarderV3.scif` — now uses `_PROTOCOL_ADAPTER_V3`

**Fix applied**: Added `address{this} _PROTOCOL_ADAPTER_V3` field, stored `paV3Addr` in the constructor via `endorse(paV3Addr, sender -> this)`, and updated both `setEmergencyCaller` and `forwardEmergencyCall` to check `_PROTOCOL_ADAPTER_V3.isEmergencyStopped()`.

---

## Model Gaps

### GAP-1: abi.decode Step Is Entirely Absent — Calldata Parsing Attack Surface Hidden

The SCIF model receives wrap/unwrap parameters as individual typed function arguments. The real Solidity does:
```solidity
(CallType callType, IERC20 token, uint128 amount) =
    abi.decode(input[:_GENERIC_INPUT_OFFSET], (CallType, IERC20, uint128));
```
This decoding is invisible to SCIF's type system. The relevant attack surfaces omitted:
1. **Input length manipulation**: `ERC20Forwarder.sol:134` — `_checkLength` gates specific inputs; a crafted `input` bytes that passes the outer length check but fails `_checkLength` would revert inside `_wrap`/`_unwrap`. The ZK circuit must also bind `input.length` or an attacker could submit inputs with extra trailing data.
2. **Enum out-of-range decoding**: Solidity reverts on enum values outside the defined range. The SCIF model uses plain `uint` comparisons. A revert here could be triggered by a valid ZK proof with an invalid callType, depending on whether the circuit binds the full enum value.
3. **Token address as a zero/malicious contract**: `token` is decoded from calldata and used for `balanceOf`, `transfer`, and Permit2. A malicious ERC20 at this address can run arbitrary code during the Permit2 flow or the `safeTransfer` call.

**Files**: `ERC20Forwarder.scif` (limitation #3, line 6) vs `ERC20Forwarder.sol:100-103`, `133-136`, `161-164`.

---

### GAP-2: Forwarder→ERC20 Deputy Chain Is Not Modeled

The SCIF model correctly captures the PA→Forwarder CDA. It does not model the Forwarder→ERC20 token deputy chain. When `_wrap` calls `Permit2.permitWitnessTransferFrom(token, amount, owner, ...)`, Permit2 then calls `ERC20.transferFrom(owner, forwarder, amount)`. The forwarder has induced Permit2 to act as a deputy for the `owner` address. If the `token` address is a malicious contract, its `transferFrom` can:
- Call back into the forwarder (blocked by `nonReentrant` on the forwarder, but not on PA)
- Call into PA's `execute` function (PA's transient slot is set, so this is blocked by PA's own `nonReentrant`)
- Emit false events or manipulate oracle state

The SCIF `IPermit2` interface (lines 34-44 of `ERC20Forwarder.scif`) models Permit2 as a simple void call with no trust authority annotation. The actual call chain is:
```
PA (trusted) → Forwarder (trusted via PA) → Permit2 (trusted address) → ERC20 (untrusted)
```
The ERC20 at the end of this chain is fully user-controlled and can execute arbitrary code.

---

### GAP-3: V3's `forwardEmergencyCall` SCIF Model Does Not Dispatch to Migration Logic — ACKNOWLEDGED

> **Status**: Acknowledged with a documentation note in the SCIF model. Full dispatch modeling would require decoding `callType` from `endorsedInput` and routing to `_migrateV1`/`_migrateV2`/Wrap/Unwrap, which is blocked by SCIF's lack of `abi.decode` support (GAP-1).

`ERC20ForwarderV3.scif` shows `forwardEmergencyCall` returning `endorsedInput` directly — it does not call `_migrateV1`, `_migrateV2`, or any token transfer logic. The real `ERC20ForwarderV3._forwardEmergencyCall` delegates to `_forwardCall` (line 179 of `ERC20Forwarder.sol`), which can execute Wrap, Unwrap, MigrateV1, or MigrateV2. The SCIF model cannot reason about the information flow through the emergency migration dispatch path in V3, which is precisely the path that combines the V3 bug with the write-wrong-root scenario.

---

### GAP-4: V3's `_migrateV1` Does Not Track V1 Nullifiers in V3's Own Set

In `ERC20ForwarderV3._migrateV1` (Solidity lines 126-149), V3 delegates entirely to `_ERC20_FORWARDER_V2.forwardEmergencyCall`. V2 internally calls its own `_migrateV1`, which adds the V1 nullifier to V2's `NullifierSet`. V3 never adds the V1 nullifier to its own `NullifierSet`. If V3 becomes the active contract and V2 is deprecated or re-initialized in a future upgrade, V3's own nullifier set would not contain V1 nullifiers — potentially allowing re-migration of V1 resources in a hypothetical future V4 that checks V3's set but not V2's.

---

## Additional Attack Surface Analysis

### EIP-1153 Transient Storage Boundary (PA → Forwarder)

PA uses `ReentrancyGuardTransient` (EIP-1153), which sets a transient storage slot during `execute`. This slot lives in the PA's own storage space. When PA calls `IForwarder(forwarder).forwardCall(...)`, the forwarder is a separate contract with its own storage. PA's transient slot does NOT prevent re-entry into the forwarder — it only prevents re-entry into PA's `execute`. The forwarder independently protects itself via its own `nonReentrant` modifier (modeled in SCIF as `lock(this)` in `_forwardCall`).

**SCIF models this correctly**: each contract's `lock(this)` is scoped to that contract's integrity domain. But reviewers should not assume PA's reentrancy guard transitively protects downstream callees.

**Note**: PA's `emergencyStop()` does not carry the `nonReentrant` modifier — it is gated only by `onlyOwner` and `whenNotPaused`. During the call chain `PA.execute` → `Forwarder.forwardCall` → `Permit2` → `ERC20.transferFrom`, a malicious ERC20 token could theoretically call back to `emergencyStop()` if the callback address coincides with the PA's owner. This would set `_paused = true` mid-execution; the current `execute` call would still complete (its pause check already passed), but subsequent transactions would be blocked. This is not exploitable — the stop is one-directional and idempotent — but the reentrancy guard boundary does not cover `emergencyStop()`.

### Reentrancy via Malicious ERC20 Token Callbacks During Permit2 Flow

When `_wrap` calls Permit2, Permit2 calls `ERC20.transferFrom(owner, forwarder, amount)`. If `token` is a malicious contract (user-controlled address endorsed via ZK proof — see HIGH-1), its `transferFrom` can execute arbitrary code. The forwarder's `lock(this)` blocks re-entry into the forwarder. PA's transient slot blocks re-entry into `execute`. However, the SCIF model does not verify this cross-contract reentrancy protection — it models the Permit2 call as a simple `void` call via `IPermit2`.

**Risk**: Medium. Existing guards likely protect against this, but the SCIF model cannot confirm it.

### Gas Griefing in Forwarder Call Loop

The real PA loops over `externalPayloads[]` and calls `_executeForwarderCall` for each entry. The SCIF model handles only a single forwarder call. A transaction with many payloads could consume excessive gas. This is outside SCIF's scope, and the caller pays for gas, so the risk is low.

### `simulateExecute` Function

The real PA has a `simulateExecute` function that always reverts (used for gas estimation). Not modeled in SCIF. Since it always reverts, it cannot modify state and poses no vulnerability.

### Permit2 Nonce Replay Across Forwarder Versions

Permit2 nonces are global to the Permit2 contract, not per-forwarder. A nonce consumed in V1 cannot be replayed in V2 or V3. Not a vulnerability.

---

## V3 Bug Impact Assessment

**Bug location**: `ERC20ForwarderV3.sol:77`
```solidity
_COMMITMENT_TREE_ROOT_V2 = ICommitmentTree(_PROTOCOL_ADAPTER_V1).latestCommitmentTreeRoot();
//                                         ^^^^^^^^^^^^^^^^ should be _PROTOCOL_ADAPTER_V2
```

**Exact root captured**: `_COMMITMENT_TREE_ROOT_V2` holds the final commitment tree root of PA_V1 at V3 deployment time, not the final root of PA_V2.

**Which V2 resources are affected**: Any V2 resource whose commitment was added to PA_V2's commitment tree after PA_V1 was stopped. Since PA_V1 stopping and PA_V2 deployment are separate events with a time gap, all V2 resources created during V2's active period (any wrap, any transfer involving a new commitment under PA_V2) have a `rootV2` value that differs from V1's final root. These resources fail the check at `ERC20ForwarderV3.sol:171`: `data.rootV2 != _COMMITMENT_TREE_ROOT_V2` → `InvalidMigrationCommitmentTreeRootV2`.

**Time window and permanence**: The bug manifests at V3 construction time and is permanent. `_COMMITMENT_TREE_ROOT_V2` is an `immutable` variable — it cannot be corrected after deployment without redeploying V3. All affected V2 resources are permanently unmigratable through V3's normal `_migrateV2` path. They can only be recovered via V3's `forwardEmergencyCall` path (which bypasses the root check entirely because the emergency caller can submit arbitrary input).

**Is there an exploitable attack using the wrong root?**
The wrong root creates a scenario where `data.rootV2 == V1's_root` is the only value that passes the root check. A user who constructs a ZK proof for a V2 resource would have `rootV2 == PA_V2's_root`, which fails. To exploit this, an attacker would need:
1. A V2-format resource committed under V1's final root (impossible post PA_V1 stop).
2. Or to submit `data.rootV2 = V1's_root` in a ZK proof — the compliance circuit verifies that `rootV2` is a historical PA root. V1's root is in PA_V3's historical roots set if it was imported. If it is, an attacker could in principle construct a V2-format ZK proof referencing V1's root. However, the logic reference check (`data.logicRefV2 == _LOGIC_REFERENCE_V2`) still requires the V2 forwarder's specific logic ref, and the ZK proof for a V1-format resource would use V1's logic ref. So this path is blocked by the logicRef check — unless the same logicRef is shared between V1 and V2 forwarders (which would be unusual).

**Conclusion**: The primary impact is **permanent denial of migration** for legitimate V2 resource holders. It is not a direct fund-drain vector under normal execution. Under the emergency path, the emergency caller can recover funds regardless (bypassing all migration checks), so total fund loss from the bug alone requires the emergency committee to be active and cooperative.

---

## Verdict

**Contracts (Solidity)**: The Solidity contracts implement correct CEI ordering, proper nonReentrant guards using EIP-1153 transient storage, and the access control gate via `msg.sender == _PROTOCOL_ADAPTER` / `msg.sender == _emergencyCaller` is sound. The V3 constructor bug at line 77 is a real defect that permanently breaks the V2 migration path and requires redeployment to fix.

**SCIF Models**: The models correctly surface the endorsement structure of all trust boundaries. The most valuable output is the enumeration of the 16 endorsement sites whose soundness depends entirely on the ZK circuit — this is the primary action item for the security posture of the protocol. MED-3 (missing V3 PA address) has been fixed. Two remaining accuracy gaps: the absent migration dispatch in V3's emergency call (GAP-3, blocked by lack of `abi.decode` support) and the missing abi.decode modeling (GAP-1).

**Information flow property violations**: No formal IFC violations were found in the Solidity that represent immediately exploitable vulnerabilities independent of the committee trust assumption. The architecture is designed so that the emergency committee is the root of trust for the recovery path, and that trust is correctly modeled as a single-actor privilege with no on-chain check against abuse. CRIT-1 is the most serious finding: the committee can drain funds without any on-chain delay or multi-party coordination, and the SCIF model makes this single-step trust chain inescapably visible.
