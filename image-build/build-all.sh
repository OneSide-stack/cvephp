#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/image-build/build-attacker.sh"
"$ROOT/image-build/build-target.sh" 8.2.34 target-php-8.2.34.iso
if [[ "${BUILD_PATCHED:-1}" == 1 ]]; then
  "$ROOT/image-build/build-target.sh" 8.2.35 target-php-8.2.35.iso
fi
node "$ROOT/scripts/generate-asset-manifest.mjs"
node "$ROOT/scripts/verify-assets.mjs"
