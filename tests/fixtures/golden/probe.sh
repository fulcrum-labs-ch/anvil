#!/usr/bin/env bash
set -euo pipefail
# anvil module: golden

# check: do a thing
if true; then
  printf 'OK: %s\n' 'do a thing'
else
  printf 'DRIFTED: %s\n' 'do a thing'
fi

# file: /etc/golden-static
__path='/etc/golden-static'
if [ -L "$__path" ]; then
  printf 'DRIFTED: %s is a symlink; anvil refuses to manage a symlinked path\n' "$__path"
elif [ -f "$__path" ] && cmp -s "$__path" <(printf '%s' 'a2V5ID0gdmFsdWUK' | base64 -d) && [ "$(stat -c '%a' "$__path")" = '640' ] && [ "$(stat -c '%U:%G' "$__path")" = 'root:root' ]; then
  printf 'OK: %s up to date\n' "$__path"
elif [ -f "$__path" ]; then
  printf 'DRIFTED: %s content, mode, or owner differs\n' "$__path"
else
  printf 'DRIFTED: %s missing\n' "$__path"
fi

# file: /etc/golden-computed
__path='/etc/golden-computed'
__desired=$(printf 'generated\n')
if [ -L "$__path" ]; then
  printf 'DRIFTED: %s is a symlink; anvil refuses to manage a symlinked path\n' "$__path"
elif [ -f "$__path" ] && [ "$(cat "$__path")" = "$__desired" ] && [ "$(stat -c '%a' "$__path")" = '644' ] && [ "$(stat -c '%U:%G' "$__path")" = 'root:root' ]; then
  printf 'OK: %s up to date\n' "$__path"
elif [ -f "$__path" ]; then
  printf 'DRIFTED: %s content, mode, or owner differs\n' "$__path"
else
  printf 'DRIFTED: %s missing\n' "$__path"
fi
