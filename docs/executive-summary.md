# Executive Summary

## What we did

We rewrote the security-critical core of two Anoma smart contracts — the
EVM Protocol Adapter (PA) and the ERC20 Forwarder — in
[SCIF](https://github.com/apl-cornell/SCIF), a language that compiles to
Solidity and forces every trust decision to be written down explicitly.

"Security-critical core" means every code path that controls who may call
what, where user-supplied data gains trust, where tokens move, and what
prevents reentrancy — roughly 60% of Solidity functions by count, but
close to 100% of the paths that affect fund safety. The unmodeled
remainder is view getters, gas simulation, event emission, and
proof-aggregation mechanics, none of which affect trust flow.

Seven SCIF models were produced, covering the PA (both a minimal
endorsement sketch and an expanded compliance/state model), the forwarder,
the emergency migration chain (V1-V3), and the cross-contract call between
PA and forwarder.

## What we found

1. **16 trust assumptions that depend on the ZK circuit** (HIGH-1). The PA
   endorses 6 user-supplied fields after proof verification; the forwarder
   endorses 10 more after checking `msg.sender == PA`. Each endorsement is
   only valid if the RISC Zero circuit constrains the corresponding field.
   No existing audit tool produces this list — SCIF does.

2. **Emergency committee can drain funds in two transactions** (CRIT-1). A
   single committee key can appoint an emergency caller who immediately
   drains all token balances. The contract enforces no time-lock or
   multi-party gate. Today this is mitigated off-chain by a multisig, but
   the contract itself provides no such guarantee. Additionally,
   `isEmergencyStopped()` returns true when the RISC Zero verifier is
   paused — meaning a third party (verifier governance) can open this drain
   window without the protocol's own `emergencyStop()` being called.

3. **Classic confused-deputy attack surface** (HIGH-2). The PA calls a
   forwarder address decoded from user calldata. If the ZK circuit does not
   constrain this address, an attacker can redirect PA calls to a malicious
   contract. An on-chain allowlist would eliminate this risk independent of
   the circuit.

4. **V3 constructor bug** (HIGH). Line 77 of `ERC20ForwarderV3.sol` reads
   the commitment tree root from the wrong Protocol Adapter (V1 instead of
   V2). This permanently blocks migration of all V2 resources. Requires
   redeployment to fix.

## What to do next (priority order)

1. **Audit the ZK circuit against the 16-field checklist.** For each
   endorsed field, confirm it appears as a constrained output in the RISC
   Zero guest journal. Any missing field means an attacker controls that
   value despite the on-chain endorsement.

2. **Add an on-chain forwarder allowlist** in the PA, independent of the ZK
   circuit.

3. **Redeploy V3** with the corrected root read (`_PROTOCOL_ADAPTER_V2`
   instead of `V1`).

4. **Consider adding a time-lock** between `setEmergencyCaller` and the
   first `forwardEmergencyCall`.

## Scope and limitations

This is a *research preview*, not a full audit. SCIF cannot analyze the ZK
circuit, economic attacks (MEV, sandwiching), gas griefing, or the
`abi.decode` step. The analysis complements — not replaces — the existing
Nethermind and Informal Systems audits. See the
[full report](../doc/report.tex) for details.
