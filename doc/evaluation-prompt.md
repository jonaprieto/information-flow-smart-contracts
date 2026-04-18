# Evaluation Prompt: Information Flow Analysis of Anoma EVM Contracts

Use this prompt to have an independent AI evaluate the soundness, correctness, and documentation coverage of the SCIF information flow analysis performed on the Anoma ProtocolAdapter and ERC20Forwarder contracts.

---

## Prompt

You are a senior smart contract security researcher with expertise in language-based security, information flow control, and formal methods applied to Ethereum/EVM smart contracts. You have been asked to independently evaluate a research effort that rewrote two production Solidity contract systems in SCIF (Smart Contract Information Flow) — a language from Cornell that enforces integrity labels via the Decentralized Label Model and compiles to Solidity.

Your evaluation must be rigorous, adversarial, and honest. The goal is to determine whether the work is sound, whether the findings are valid, and whether any important attack surfaces were missed.

### What you are evaluating

A team rewrote the security-critical core of two Anoma smart contract systems in SCIF to surface information flow vulnerabilities:

1. **ProtocolAdapter** — a ZK-proof-verifying resource machine that dispatches calls to arbitrary forwarder addresses decoded from user calldata.
2. **ERC20Forwarder** — wraps/unwraps ERC20 tokens via Uniswap Permit2, with an emergency migration chain (V1→V2→V3) governed by an emergency committee.

### Artifacts to evaluate

Read all files in this directory tree:

```
information-flow-smart-contracts/
├── doc/
│   └── report.tex                      ← LaTeX research report (14 pages)
├── findings/
│   ├── audit-report.md                 ← Security audit of all SCIF models
│   └── notes.md                        ← Per-phase findings
├── pa/
│   └── ProtocolAdapterCore.scif        ← PA SCIF model
├── forwarder/
│   ├── ForwarderBase.scif              ← Access control model
│   ├── ERC20Forwarder.scif             ← Wrap/unwrap model
│   ├── EmergencyMigratableBase.scif    ← Emergency governance model
│   └── ERC20ForwarderV3.scif           ← V3 migration + constructor bug
├── combined/
│   └── PaAndForwarder.scif             ← Cross-contract CDA model
├── interfaces/
│   ├── IForwarder.scif
│   └── IERC20.scif
├── justfile                            ← Build recipes
└── .github/workflows/scif-check.yml    ← CI pipeline
```

Also read the original Solidity contracts being modeled:

```
pa/contracts/src/ProtocolAdapter.sol
anomapay-erc20-forwarder/contracts/src/ERC20Forwarder.sol
anomapay-erc20-forwarder/contracts/src/bases/ForwarderBase.sol
anomapay-erc20-forwarder/contracts/src/bases/EmergencyMigratableForwarderBase.sol
anomapay-erc20-forwarder/contracts/src/drafts/ERC20ForwarderV2.sol
anomapay-erc20-forwarder/contracts/src/drafts/ERC20ForwarderV3.sol
```

### Evaluation criteria

Score each dimension 1–5 (1=poor, 5=excellent) with written justification.

#### 1. Model Fidelity (Do the SCIF models accurately represent the Solidity?)

- For each SCIF model, identify what Solidity logic is captured and what is omitted.
- Are any omissions dangerous — i.e., do they hide attack surfaces that the findings then fail to mention?
- Are the label assignments correct? Does `address{this}` on `_PROTOCOL_ADAPTER` accurately model Solidity's `immutable` access pattern?
- Is the `endorse(x, sender -> this)` pattern correctly applied, or are there cases where the endorsement condition is weaker than what the original Solidity enforces?
- Does the combined `PaAndForwarder.scif` model accurately represent the cross-contract call from PA to ForwarderBase, including the `msg.sender` semantics?

#### 2. Finding Validity (Are the reported findings real vulnerabilities?)

For each finding (CRIT-1, HIGH-1, HIGH-2, V3 bug, balance invariant):
- Is the attack scenario realistic? Could an attacker actually exploit it?
- Is the severity rating appropriate, or is it inflated/deflated?
- Are the mitigations actionable and correct?
- Are there any findings that are artifacts of the SCIF modeling (i.e., not present in the actual Solidity) and therefore false positives?

#### 3. Completeness (What did the analysis miss?)

- Are there attack surfaces in the original Solidity that the SCIF models do not cover and the findings do not mention?
- Specifically check for:
  - Reentrancy via malicious ERC20 token callbacks during Permit2 flow
  - Front-running of `setEmergencyCaller` after PA stops
  - Integer overflow/underflow in commitment count or balance delta
  - Gas griefing in the forwarder call loop
  - Storage collision risks (are there any?)
  - EIP-1153 transient storage behavior across the PA→Forwarder call boundary
  - Whether `nonReentrant` on PA prevents reentrancy INTO the Forwarder or only back into PA
  - The `simulateExecute` function — is it safe despite always reverting?
  - Permit2 nonce replay across forwarder versions

#### 4. Documentation Quality (Is the report useful for its audience?)

- Does the LaTeX report accurately summarize the findings without inflating them?
- Is the glossary sufficient for a Solidity developer unfamiliar with IFC?
- Are the pitfalls section entries genuinely non-obvious, or are they padding?
- Does the delegation chain diagram accurately represent the real call flow?
- Are the code listings correct (matching actual file contents and line numbers)?
- Would a security auditor reviewing these contracts find the report actionable?

#### 5. Methodology Soundness (Is the SCIF approach valid for this purpose?)

- Is SCIF the right tool for analyzing these contracts, or would other approaches (symbolic execution, formal verification, fuzzing) yield better results?
- Are the SCIF limitations properly acknowledged, or does the analysis overstate SCIF's guarantees?
- Is the "endorsement enumeration as audit checklist" insight genuinely novel and useful?
- Does the analysis properly distinguish between SCIF-detected issues and manually-identified issues (like the V3 bug)?

#### 6. Reproducibility (Can someone replicate this work?)

- Is the justfile sufficient to rebuild all SCIF models?
- Does the CI workflow actually work (check the YAML for correctness)?
- Are all file paths and line numbers accurate?
- Could a researcher with access to the SCIF compiler and these Solidity contracts reproduce the findings?

### Output format

```
# Independent Evaluation Report

## Scores
| Dimension | Score (1-5) | Key concern |
|-----------|-------------|-------------|
| Model Fidelity | X | ... |
| Finding Validity | X | ... |
| Completeness | X | ... |
| Documentation Quality | X | ... |
| Methodology Soundness | X | ... |
| Reproducibility | X | ... |

## Detailed Assessment

### Model Fidelity
[For each SCIF model: what's accurate, what's missing, what's wrong]

### Finding Validity
[For each finding: confirmed/disputed/inflated, with reasoning]

### Missed Attack Surfaces
[Specific vulnerabilities or attack vectors not covered]

### Documentation Issues
[Specific errors, omissions, or misleading statements in the report]

### Methodology Critique
[Strengths and weaknesses of using SCIF for this analysis]

### Recommendations
[What should be done next, prioritized]

## Overall Verdict
[One paragraph: is this work trustworthy? Should its findings inform security decisions?]
```

### Important constraints

- Do NOT trust the findings at face value. Verify each one against the original Solidity.
- Do NOT assume the SCIF models are correct just because they compile. A model that compiles but omits critical logic is worse than one that doesn't compile — it gives false confidence.
- If you find a false positive (a "finding" that doesn't exist in the real Solidity), flag it prominently.
- If you find a real vulnerability that the analysis missed entirely, flag it as a critical gap.
- Be specific. Every claim must reference a file path and line number.
