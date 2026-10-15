#!/bin/bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
output="${1:-$project_dir/dist/IdriveCore.xcframework}"
if [[ -e "$output" ]]; then
  echo "Output already exists: $output" >&2
  exit 1
fi
cargo build --release --features ffi --lib
cargo build --release --features ffi --target aarch64-apple-ios --lib
cargo build --release --features ffi --target aarch64-apple-ios-sim --lib
mkdir -p "$(dirname "$output")"
xcodebuild -create-xcframework \
  -library "$project_dir/target/release/libidrive_core.a" -headers "$project_dir/include" \
  -library "$project_dir/target/aarch64-apple-ios/release/libidrive_core.a" -headers "$project_dir/include" \
  -library "$project_dir/target/aarch64-apple-ios-sim/release/libidrive_core.a" -headers "$project_dir/include" \
  -output "$output"
