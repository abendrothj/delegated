#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
if [[ -z "${version}" ]]; then
  echo "failed to parse crate version from Cargo.toml" >&2
  exit 1
fi

expected_tag="v${version}"
head_commit="$(git rev-parse HEAD)"

if git tag --points-at HEAD | grep -q '^v'; then
  if ! git tag --points-at HEAD | grep -qx "${expected_tag}"; then
    echo "HEAD is tagged, but not with expected ${expected_tag}" >&2
    exit 1
  fi
fi

if [[ "${DELEGATED_REQUIRE_VERSION_TAG_ON_HEAD:-0}" == "1" ]]; then
  tag_commit="$(git rev-list -n 1 "${expected_tag}" 2>/dev/null || true)"
  if [[ -z "${tag_commit}" ]]; then
    echo "required tag ${expected_tag} does not exist" >&2
    exit 1
  fi
  if [[ "${tag_commit}" != "${head_commit}" ]]; then
    echo "required release provenance mismatch: ${expected_tag} points to ${tag_commit}, HEAD is ${head_commit}" >&2
    exit 1
  fi
fi

echo "Release provenance check passed for version ${version}."
