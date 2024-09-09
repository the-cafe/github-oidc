#!/bin/bash
set -euo pipefail

if ! command -v cargo-semver-checks &> /dev/null
then
    echo "cargo-semver-checks is not installed. Installing now..."
    cargo install cargo-semver-checks
fi

# Run cargo-semver-checks
echo "Running cargo-semver-checks..."
cargo semver-checks

# If cargo-semver-checks passes, proceed with publishing
if [ $? -eq 0 ]; then
    echo "cargo-semver-checks passed. Proceeding with publish..."
    cargo publish
else
    echo "cargo-semver-checks failed. Please review and fix any issues before publishing."
    exit 1
fi
