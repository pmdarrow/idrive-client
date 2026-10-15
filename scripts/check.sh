#!/bin/bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

cargo fmt --all -- --check
cargo lint
# Check the portable codec with the native client disabled as well.
cargo clippy --locked --all-targets --no-default-features -- -D warnings
