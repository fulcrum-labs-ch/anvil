#!/usr/bin/env bash
set -euo pipefail
# anvil module: golden
__created_list=${ANVIL_STATE_DIR:-'/var/lib/anvil'}/created
__anvil_created() { grep -qsxF -- "$1" "$__created_list"; }
__anvil_remember() { __anvil_created "$1" || { mkdir -p "$(dirname "$__created_list")" && printf '%s\n' "$1" >> "$__created_list"; } || true; }
__anvil_forget() { [ -f "$__created_list" ] || return 0; grep -vxF -- "$1" "$__created_list" > "$__created_list.tmp" 2>/dev/null || true; [ -f "$__created_list.tmp" ] && mv -f "$__created_list.tmp" "$__created_list" 2>/dev/null || true; }

# rollback: /etc/golden-computed
__path='/etc/golden-computed'
if [ -f "$__path.anvil.bak" ]; then
  cp -a "$__path.anvil.bak" "$__path"
  rm -f "$__path.anvil.bak"
  printf 'CHANGED: %s restored from backup\n' "$__path"
elif [ -L "$__path" ]; then
  printf 'OK: %s is a symlink anvil does not manage; left alone\n' "$__path"
elif [ -e "$__path" ] && { __anvil_created "$__path" \
  || grep -qsF "$(printf 'Created\t%s\t' "$__path")" "${ANVIL_STATE_DIR:-/var/lib/anvil}"/runs/*; }; then
  rm -f "$__path"
  printf 'CHANGED: %s removed (created by anvil, no backup)\n' "$__path"
elif [ -e "$__path" ]; then
  # No backup and no record of anvil creating it — never delete.
  printf 'OK: %s was not created by anvil and has no backup; left in place\n' "$__path"
else
  printf 'OK: %s nothing to roll back\n' "$__path"
fi
__anvil_forget "$__path"

# rollback: /etc/golden-static
__path='/etc/golden-static'
if [ -f "$__path.anvil.bak" ]; then
  cp -a "$__path.anvil.bak" "$__path"
  rm -f "$__path.anvil.bak"
  printf 'CHANGED: %s restored from backup\n' "$__path"
elif [ -L "$__path" ]; then
  printf 'OK: %s is a symlink anvil does not manage; left alone\n' "$__path"
elif [ -e "$__path" ] && { __anvil_created "$__path" \
  || grep -qsF "$(printf 'Created\t%s\t' "$__path")" "${ANVIL_STATE_DIR:-/var/lib/anvil}"/runs/*; }; then
  rm -f "$__path"
  printf 'CHANGED: %s removed (created by anvil, no backup)\n' "$__path"
elif [ -e "$__path" ]; then
  # No backup and no record of anvil creating it — never delete.
  printf 'OK: %s was not created by anvil and has no backup; left in place\n' "$__path"
else
  printf 'OK: %s nothing to roll back\n' "$__path"
fi
__anvil_forget "$__path"

# rollback (command-edited): /etc/golden-edited
__path='/etc/golden-edited'
if [ -f "$__path.anvil.bak" ]; then
  cp -a "$__path.anvil.bak" "$__path"
  rm -f "$__path.anvil.bak"
  printf 'CHANGED: %s restored from backup\n' "$__path"
elif [ -f "$__path" ] && __anvil_created "$__path"; then
  rm -f "$__path"
  __anvil_forget "$__path"
  printf 'CHANGED: %s removed (anvil created it)\n' "$__path"
else
  printf 'OK: %s nothing to roll back\n' "$__path"
fi
printf 'CHANGED: custom rollback\n'

# reload with the restored config: golden reload
if { true
} && { echo reloaded
}; then
  printf 'OK: %s reloaded with the restored config\n' 'golden reload'
else
  printf 'FAILED: %s restored config did not validate or reload\n' 'golden reload'
  exit 1
fi
