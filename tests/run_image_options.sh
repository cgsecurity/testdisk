#!/bin/sh
# Run after ./configure; builds only a synthetic options/session test executable.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/photorec-image-options.XXXXXXXX")
trap 'rm -rf -- "$build_dir"' EXIT HUP INT TERM
"${CC:-cc}" -DHAVE_CONFIG_H -I"$repo_dir" -I"$repo_dir/src" \
  -O2 -Wall -Wextra -ffunction-sections -fdata-sections \
  "$repo_dir/tests/test_image_options.c" "$repo_dir/src/poptions.c" \
  "$repo_dir/src/common.c" "$repo_dir/src/sessionp.c" \
  -Wl,--gc-sections -o "$build_dir/test_image_options"
cd "$build_dir"
./test_image_options
