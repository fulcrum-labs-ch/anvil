#!/usr/bin/env bash
set -euo pipefail
# anvil module: golden
__ts=$(date +%Y%m%dT%H%M%S 2>/dev/null || echo now)
__manifest='/var/lib/anvil/runs'/golden.$__ts
mkdir -p '/var/lib/anvil/runs' 2>/dev/null || true
: > "$__manifest" 2>/dev/null || __manifest=/dev/null
__reverts=()
__creates=()
__rundir=$(mktemp -d /var/lib/anvil/revert.XXXXXX 2>/dev/null || mktemp -d)
trap 'rm -rf "$__rundir"; [ "$__manifest" = /dev/null ] || [ -s "$__manifest" ] || rm -f "$__manifest"' EXIT
__created_list=${ANVIL_STATE_DIR:-'/var/lib/anvil'}/created
__anvil_created() { grep -qsxF -- "$1" "$__created_list"; }
__anvil_remember() { __anvil_created "$1" || { mkdir -p "$(dirname "$__created_list")" && printf '%s\n' "$1" >> "$__created_list"; } || true; }
__anvil_forget() { [ -f "$__created_list" ] || return 0; grep -vxF -- "$1" "$__created_list" > "$__created_list.tmp" 2>/dev/null || true; [ -f "$__created_list.tmp" ] && mv -f "$__created_list.tmp" "$__created_list" 2>/dev/null || true; }

# converge: do a thing
if true; then
  printf 'OK: %s (already)\n' 'do a thing'
else
echo done
  printf '%s\t%s\n' cmd 'do a thing' >> "$__manifest"
  printf 'CHANGED: %s\n' 'do a thing'
fi
__path='/etc/golden-static'
if [ -L "$__path" ]; then
  printf 'FAILED: %s is a symlink; refusing to manage a symlinked path\n' "$__path"
  exit 1
fi
__path='/etc/golden-computed'
if [ -L "$__path" ]; then
  printf 'FAILED: %s is a symlink; refusing to manage a symlinked path\n' "$__path"
  exit 1
fi

# file: /etc/golden-static
__path='/etc/golden-static'
__verb=''
if [ -f "$__path" ] && cmp -s "$__path" <(printf '%s' 'a2V5ID0gdmFsdWUK' | base64 -d); then
  : # content already correct
else
  # New parent dirs 0755 whatever the host umask (CIS sets 0007 or 027), so
  # files meant for service users stay reachable; the file's own mode guards it.
  (umask 022 && mkdir -p "$(dirname "$__path")")
  if [ -f "$__path" ]; then
   cp -a "$__path" "$__rundir/${__path//\//%}"
   # Keep the pristine original — back up on the first change
   # only, and never for a file anvil itself created.
   if [ ! -e "$__path.anvil.bak" ] && ! __anvil_created "$__path"; then
    cp -a "$__path" "$__path.anvil.bak"
   fi
   __reverts+=("$__path")
   __verb=Modified
  else
   __creates+=("$__path")
   __anvil_remember "$__path"
   __verb=Created
  fi
  printf '%s' 'a2V5ID0gdmFsdWUK' | base64 -d > "$__path"
fi
if [ "$(stat -c '%a' "$__path")" != '640' ] || ! [ "$(stat -c '%U:%G' "$__path")" = 'root:root' ]; then
  if [ -z "$__verb" ]; then
   # Mode/owner-only fix; the copy keeps both so the guard can revert
   cp -a "$__path" "$__rundir/${__path//\//%}"
   # A pre-existing file needs its pristine mode/owner kept too,
   # or rollback has no backup and would treat it as anvil-created.
   if [ ! -e "$__path.anvil.bak" ] && ! __anvil_created "$__path"; then
    cp -a "$__path" "$__path.anvil.bak"
   fi
   __reverts+=("$__path")
   __verb=Modified
  fi
fi
chown 'root:root' "$__path"
chmod '0640' "$__path"
if [ -n "$__verb" ]; then
  printf '%s\t%s\t%s\n' "$__verb" "$__path" "$__ts" >> "$__manifest"
  printf 'CHANGED: %s (%s)\n' "$__path" "$__verb"
else
  printf 'OK: %s already correct\n' "$__path"
fi

# file: /etc/golden-computed
__path='/etc/golden-computed'
__desired=$(printf 'generated\n')
__verb=''
if [ -f "$__path" ] && [ "$(cat "$__path")" = "$__desired" ]; then
  : # content already correct
else
  # New parent dirs 0755 whatever the host umask (CIS sets 0007 or 027), so
  # files meant for service users stay reachable; the file's own mode guards it.
  (umask 022 && mkdir -p "$(dirname "$__path")")
  if [ -f "$__path" ]; then
   cp -a "$__path" "$__rundir/${__path//\//%}"
   # Keep the pristine original — back up on the first change
   # only, and never for a file anvil itself created.
   if [ ! -e "$__path.anvil.bak" ] && ! __anvil_created "$__path"; then
    cp -a "$__path" "$__path.anvil.bak"
   fi
   __reverts+=("$__path")
   __verb=Modified
  else
   __creates+=("$__path")
   __anvil_remember "$__path"
   __verb=Created
  fi
  printf '%s\n' "$__desired" > "$__path"
fi
if [ "$(stat -c '%a' "$__path")" != '644' ] || ! [ "$(stat -c '%U:%G' "$__path")" = 'root:root' ]; then
  if [ -z "$__verb" ]; then
   # Mode/owner-only fix; the copy keeps both so the guard can revert
   cp -a "$__path" "$__rundir/${__path//\//%}"
   # A pre-existing file needs its pristine mode/owner kept too,
   # or rollback has no backup and would treat it as anvil-created.
   if [ ! -e "$__path.anvil.bak" ] && ! __anvil_created "$__path"; then
    cp -a "$__path" "$__path.anvil.bak"
   fi
   __reverts+=("$__path")
   __verb=Modified
  fi
fi
chown 'root:root' "$__path"
chmod '0644' "$__path"
if [ -n "$__verb" ]; then
  printf '%s\t%s\t%s\n' "$__verb" "$__path" "$__ts" >> "$__manifest"
  printf 'CHANGED: %s (%s)\n' "$__path" "$__verb"
else
  printf 'OK: %s already correct\n' "$__path"
fi

# guarded reload: golden reload
if { true
} && { echo reloaded
}; then
  printf 'OK: %s validated and reloaded\n' 'golden reload'
else
  printf 'FAILED: %s validation or reload failed, reverting\n' 'golden reload' >&2
  for __c in "${__creates[@]:-}"; do
   [ -n "$__c" ] || continue
   rm -f "$__c"
   __anvil_forget "$__c"
  done
  for __r in "${__reverts[@]:-}"; do
   [ -n "$__r" ] || continue
   if [ -f "$__rundir/${__r//\//%}" ]; then cp -a "$__rundir/${__r//\//%}" "$__r";
   elif [ -f "$__r.anvil.bak" ]; then mv -f "$__r.anvil.bak" "$__r"; else rm -f "$__r"; fi
  done
  exit 1
fi
