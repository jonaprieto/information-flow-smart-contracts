# SCIF Information Flow Analysis for Anoma Contracts
#
# Requires:
#   - Java 21 (temurin recommended)
#   - Gradle (via SCIF's wrapper)
#   - SCIF compiler cloned at $SCIF_DIR (default: ../forks/SCIF)
#
# Vendored references (as git submodules under third_party/):
#   - anoma/pa-evm                    original PA Solidity
#   - anoma/anomapay-erc20-forwarder  original forwarder Solidity
# Run `just init` once after cloning to fetch them.

SCIF_DIR := env("SCIF_DIR", justfile_directory() + "/../forks/SCIF")
OUT_DIR := justfile_directory() + "/tmp"
PA_SRC := justfile_directory() + "/third_party/pa-evm/contracts/src"
FWD_SRC := justfile_directory() + "/third_party/anomapay-erc20-forwarder/contracts/src"

# List all available recipes
default:
    @just --list

# Initialise / update the vendored contract submodules (run once after clone)
init:
    @echo "Initialising submodules (pa-evm, anomapay-erc20-forwarder)..."
    git submodule update --init --recursive
    @echo "OK: contracts available at third_party/pa-evm and third_party/anomapay-erc20-forwarder"

# Fast-forward vendored submodules to their upstream main branch
update-contracts:
    git submodule update --remote --merge third_party/pa-evm
    git submodule update --remote --merge third_party/anomapay-erc20-forwarder

# Show the paths of the vendored Solidity files (useful for referencing)
show-contracts:
    @echo "Protocol Adapter:"
    @find "{{PA_SRC}}" -name '*.sol' 2>/dev/null | sed 's|{{PA_SRC}}/||' | sed 's|^|  |' || echo "  (run 'just init' first)"
    @echo "ERC20 Forwarder:"
    @find "{{FWD_SRC}}" -name '*.sol' 2>/dev/null | sed 's|{{FWD_SRC}}/||' | sed 's|^|  |' || echo "  (run 'just init' first)"

# Check that Java 21 and SCIF compiler are available
check:
    @echo "Checking Java..."
    java -version 2>&1 | head -1
    @echo "Checking SCIF compiler at {{SCIF_DIR}}..."
    @test -f "{{SCIF_DIR}}/scif" || (echo "ERROR: SCIF compiler not found at {{SCIF_DIR}}" && echo "Clone it: git clone --recurse-submodules https://github.com/apl-cornell/SCIF.git {{SCIF_DIR}}" && exit 1)
    @echo "OK: SCIF compiler found"

# Build the SCIF compiler (first-time setup)
build-scif:
    cd "{{SCIF_DIR}}" && ./gradlew build -x test

# Compile a single .scif file to Solidity
compile file:
    @mkdir -p "{{OUT_DIR}}"
    cd "{{SCIF_DIR}}" && ./scif -c "{{justfile_directory()}}/{{file}}" -o "{{justfile_directory()}}/{{OUT_DIR}}/$(basename {{file}} .scif).sol"

# Typecheck a single .scif file (no Solidity output)
typecheck file:
    cd "{{SCIF_DIR}}" && ./scif -t "{{justfile_directory()}}/{{file}}"

# Compile all .scif files in the project
compile-all:
    @mkdir -p "{{OUT_DIR}}"
    @for f in $(find {{justfile_directory()}} -name '*.scif' -not -path '*/tmp/*'); do \
        echo "Compiling: $f"; \
        cd "{{SCIF_DIR}}" && ./scif -c "$f" -o "{{OUT_DIR}}/$(basename "$f" .scif).sol" 2>&1 || true; \
    done

# Typecheck all .scif files
typecheck-all:
    @for f in $(find {{justfile_directory()}} -name '*.scif' -not -path '*/tmp/*'); do \
        echo "Typechecking: $f"; \
        cd "{{SCIF_DIR}}" && ./scif -t "$f" 2>&1 || true; \
    done

# Clean generated output
clean:
    rm -rf "{{OUT_DIR}}"

# --- Phase-specific recipes ---

# Phase 1: Compile ForwarderBase
phase1:
    just compile forwarder/ForwarderBase.scif

# Phase 2: Compile PA core + combined model
phase2:
    just compile pa/ProtocolAdapterCore.scif
    just compile combined/PaAndForwarder.scif

# Phase 3: Compile ERC20 forwarder model
phase3:
    just compile forwarder/ERC20Forwarder.scif

# Phase 4: Compile emergency migration models
phase4:
    just compile forwarder/EmergencyMigratableBase.scif
    just compile forwarder/ERC20ForwarderV2.scif
    just compile forwarder/ERC20ForwarderV3.scif
