#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ -z "${SIGNET_INTEROP_HTTP_URL:-}" ]]; then
  echo "Set SIGNET_INTEROP_HTTP_URL to run external interop checks." >&2
  echo "Optional: SIGNET_INTEROP_MCP_URL, SIGNET_INTEROP_A2A_URL" >&2
  exit 1
fi

echo "Running external interop checks..."
cargo test --features "client,async" --test external_interop
echo "External interop checks passed."
