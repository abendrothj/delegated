#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "Running conformance suites..."
cargo test --test conformance
cargo test --test interop_harness
cargo test --features "axum,client" --test integration_server
echo "Conformance suites passed."

