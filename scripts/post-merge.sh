#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Reconcile dependencies with the merged lockfile, without prompts.
npm ci --include=dev --no-audit --no-fund

# Includes the mandatory startup/chunk budget checks.
npm run build
