# SCIF Information Flow Analysis for Anoma Contracts
#
# Requires:
#   - Java 21 (temurin recommended)
#   - Gradle (via SCIF's wrapper)
#   - SCIF compiler cloned at $SCIF_DIR (default: ../forks/SCIF)

SCIF_DIR := env("SCIF_DIR", justfile_directory() + "/../forks/SCIF")
OUT_DIR := justfile_directory() + "/tmp"

# List all available recipes
default:
    @just --list

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
