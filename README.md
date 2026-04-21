# Information-Flow Smart Contracts — Research Preview

[![SCIF Typecheck & Compile](https://github.com/jonaprieto/information-flow-smart-contracts/actions/workflows/scif-check.yml/badge.svg?branch=main)](https://github.com/jonaprieto/information-flow-smart-contracts/actions/workflows/scif-check.yml?query=branch%3Amain)
[![Build Research Report](https://github.com/jonaprieto/information-flow-smart-contracts/actions/workflows/build-docs.yml/badge.svg?branch=main)](https://github.com/jonaprieto/information-flow-smart-contracts/actions/workflows/build-docs.yml?query=branch%3Amain)
[![SCIF compiler](https://img.shields.io/badge/SCIF-apl--cornell%2FSCIF%40latest-1565C0)](https://github.com/apl-cornell/SCIF)
[![Solidity targets](https://img.shields.io/badge/Solidity-%E2%89%A5%200.8.27-374151)](https://soliditylang.org/)
[![Status](https://img.shields.io/badge/status-research%20preview-E65100)](./doc/report.tex)

An exploratory information-flow analysis of two Anoma smart-contract systems —
the EVM **Protocol Adapter** and the **ERC20 Forwarder** — using
[**SCIF**](https://github.com/apl-cornell/SCIF) (Smart Contract Information
Flow), a language from Cornell that compiles to Solidity and enforces
integrity policies via the Decentralized Label Model.

> **Research preview.** This is not a replacement for the existing Nethermind
> and Informal Systems audits. It is a complementary, structural study whose
> primary output is an enumerable checklist of trust boundaries that must hold
> for the on-chain code to be sound — in particular the 16 endorsement sites
> that depend on the RISC Zero circuit.

## 📄 Latest report

| Artefact | Link |
|----------|------|
| **Executive summary** | [`docs/executive-summary.md`](./docs/executive-summary.md) |
| **Research report (PDF, built from `main`)** | [Download from latest successful build](https://nightly.link/jonaprieto/information-flow-smart-contracts/workflows/build-docs/main/research-report.zip) |
| Report source | [`doc/report.tex`](./doc/report.tex) |
| Run history (to grab older builds) | [`build-docs.yml` runs on main](https://github.com/jonaprieto/information-flow-smart-contracts/actions/workflows/build-docs.yml?query=branch%3Amain) |

The *Download* link above resolves via
[nightly.link](https://nightly.link/) to the artefact produced by the most
recent successful run of the `Build Research Report` workflow on `main`.
If you are signed into GitHub you can also grab the artefact directly from
the workflow's run page (`Actions` → `Build Research Report` → latest run
→ *Artifacts*).

---

## What is here

| Path | Contents |
|------|----------|
| [`pa/`](./pa) | SCIF model of the Protocol Adapter core |
| [`forwarder/`](./forwarder) | SCIF models of `ForwarderBase`, `ERC20Forwarder`, `EmergencyMigratableBase`, `ERC20ForwarderV3` |
| [`combined/`](./combined) | `PaAndForwarder.scif` — cross-contract CDA trace |
| [`interfaces/`](./interfaces) | `IForwarder`, `IERC20` SCIF interfaces |
| [`docs/`](./docs) | Executive summary (standalone markdown) |
| [`findings/`](./findings) | Audit report, per-phase notes, independent evaluation |
| [`doc/`](./doc) | LaTeX research report (compile with `xelatex`) |
| [`third_party/`](./third_party) | Submodules: [`anoma/pa-evm`](https://github.com/anoma/pa-evm), [`anoma/anomapay-erc20-forwarder`](https://github.com/anoma/anomapay-erc20-forwarder) |
| [`.github/workflows/`](./.github/workflows) | CI: typecheck + compile every `.scif` on every push/PR |
| `justfile` | Local build recipes |

---

## Getting started

### Prerequisites

- Java 21 (Temurin recommended) — required by the SCIF compiler
- [`just`](https://github.com/casey/just) — task runner
- A clone of [`apl-cornell/SCIF`](https://github.com/apl-cornell/SCIF),
  pinned to the `latest` release tag
- (Optional, for the report) XeLaTeX and the **JetBrains Mono NL** font

### Clone with submodules

```bash
git clone --recurse-submodules https://github.com/jonaprieto/information-flow-smart-contracts.git
cd information-flow-smart-contracts
just init          # idempotent; fetches third_party/pa-evm and the forwarder repo
```

If you already cloned without `--recurse-submodules`, run `just init`.

### Build the SCIF compiler (one-off)

```bash
# Clone the SCIF compiler next to this repo
git clone --branch latest --recurse-submodules https://github.com/apl-cornell/SCIF.git ../forks/SCIF
just build-scif
```

The `SCIF_DIR` environment variable overrides the default path
(`../forks/SCIF`).

### Typecheck and compile SCIF models

```bash
just check            # verify Java + SCIF compiler are reachable
just typecheck-all    # run the SCIF type-checker on every .scif file
just compile-all      # compile every .scif to Solidity under tmp/
just show-contracts   # list the vendored Solidity source paths
```

The CI workflow ([`.github/workflows/scif-check.yml`](./.github/workflows/scif-check.yml))
runs the same two commands on every push and pull request and uploads the
generated `.sol` files as a build artefact.

### Build the research report

```bash
cd doc
xelatex report.tex
xelatex report.tex   # second pass resolves cross-references
open report.pdf
```

The report uses [`fontspec`](https://ctan.org/pkg/fontspec) and expects
**JetBrains Mono NL** to be installed. Install it from
<https://www.jetbrains.com/lp/mono/> or via Homebrew Cask
(`brew install --cask font-jetbrains-mono-nl`).

---

## Key findings (summary)

| ID | Severity | What |
|----|----------|------|
| **CRIT-1** | Critical (governance) | `_EMERGENCY_COMMITTEE` can appoint an emergency caller that drains the forwarder in two transactions with no on-chain delay. Mitigated off-chain by a multisig today, but the contract itself encodes no constraint. |
| **HIGH-1** | High | 16 SCIF endorsement sites (6 in the PA, 10 in the forwarder) depend entirely on the RISC Zero circuit covering the corresponding journal outputs. SCIF enumerates them; the circuit must be audited against this list. |
| **HIGH-2** | High | Classic CDA: PA dispatches calls to a user-supplied forwarder address after ZK endorsement. Without an on-chain allowlist the CDA is live if the circuit has a gap. |
| **HIGH** | High | `ERC20ForwarderV3.sol:77` reads `_COMMITMENT_TREE_ROOT_V2` from `_PROTOCOL_ADAPTER_V1` — a copy/paste error that permanently blocks V2→V3 migration. Requires redeployment to fix. |
| **MED-1..3** | Medium | Write-once invariant is runtime-only; V3 deployment constraint is unverifiable on-chain; SCIF model for V3 emergency dispatch is incomplete. |

Full write-ups: [`findings/audit-report.md`](./findings/audit-report.md).

Independent adversarial review: [`findings/independent-evaluation.md`](./findings/independent-evaluation.md).

---

## References

- Yao, Ni, Ma, Schiff, Myers, Cecchetti — *A Language for Smart Contracts with
  Secure Control Flow*, [arXiv:2407.01204](https://arxiv.org/abs/2407.01204)
- Cecchetti, Yao, Ni, Myers — *Compositional Security for Reentrant
  Applications*, IEEE S&P 2021,
  [arXiv:2103.08577](https://arxiv.org/abs/2103.08577)
- Myers and Liskov — *A Decentralized Model for Information Flow Control*,
  SOSP 1997, [DOI 10.1145/268998.266669](https://doi.org/10.1145/268998.266669)
- Anoma — *EVM Protocol Adapter specification*,
  [specs.anoma.net](https://specs.anoma.net/main/arch/integrations/adapters/evm.html)

---

## Status & scope

This work is a **research preview**. It does not cover every attack surface of
the original contracts (see the *Missed attack surfaces* section of the
independent evaluation), does not replace existing audits, and its CI only
exercises the SCIF typechecker, not the runtime behaviour of the generated
Solidity. Findings should be read in combination with the upstream audits in
[`anoma/pa-evm/audits/`](https://github.com/anoma/pa-evm/tree/main/audits) and
[`anoma/anomapay-erc20-forwarder/audits/`](https://github.com/anoma/anomapay-erc20-forwarder/tree/main/audits).
