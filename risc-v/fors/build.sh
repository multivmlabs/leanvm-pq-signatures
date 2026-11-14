#!/bin/sh
set -eu
cd "$(dirname "$0")/guest"
cargo build --release --locked --offline
cp target/riscv64im-unknown-none-elf/release/fors ../fors.elf
