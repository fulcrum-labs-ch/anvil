#!/usr/bin/env bash
# scripts/acceptance.sh — real-host acceptance test against an EXISTING,
# DISPOSABLE Debian 13 / Ubuntu 26.04 box. It hardens the box for good: read
# docs/design/acceptance.md (every step and what it does to the host) first.
#
#   scripts/acceptance.sh --dry-run root@203.0.113.10   # print every command, touch nothing
#   scripts/acceptance.sh root@203.0.113.10             # run (asks you to type the host)
#   scripts/acceptance.sh --yes --containers --beszel --podman root@203.0.113.10
#   scripts/acceptance.sh --coding-agents admin@my-box     # only the coding-agents checks, on a box in use
#   scripts/acceptance.sh --hygiene [--greptimedb] admin@my-box  # only the hygiene checks, on a box in use
#   scripts/acceptance.sh --monitoring admin@my-box       # only the monitoring checks, on a Docker box in use
#   scripts/acceptance.sh --in-use admin@my-box           # the monitoring follow-ups, read-only
#   scripts/acceptance.sh --forgejo-sandbox admin@my-box  # only the Forgejo sandbox checks, on a Docker box in use
#
# <user@host>: a fresh box reachable on port 22 with key login, as root or a
# user with passwordless sudo. Creates the sudo user `ops` with your key and
# logs in as `ops` from then on.
# Flags: --dry-run, --yes (skip the confirmation), --containers,
# --beszel, --podman, --coding-agents (only its checks, as
# <user> on a host that already runs other modules; ssh port
# ANVIL_ACCEPT_PORT, default 22), --hygiene (only its checks, likewise;
# --greptimedb adds a temporary GreptimeDB for `retention`), --monitoring
# (GreptimeDB + Vector on 14000-14003, then rolled back), --in-use
# (read-only follow-ups: checks on a Docker host already running them),
# --forgejo-sandbox (an ephemeral forgejo_runner on a throwaway repo;
# its own Forgejo on <ip>.sslip.io unless ANVIL_ACCEPT_FORGEJO_URL and
# ANVIL_ACCEPT_FORGEJO_API_TOKEN, a token with write:repository + write:user, are set; ANVIL_ACCEPT_SANDBOX_EXTRA = path to a
# TOML file with this host's [docker]/[github_runner] sections, so daemon.json
# stays as is; ANVIL_ACCEPT_SANDBOX_RUNTIME=docker-rootless tests the
# per-slot rootless engine instead of sysbox). Env: ANVIL_ACCEPT_KEY (public key, default
# ~/.ssh/id_ed25519.pub or the first ~/.ssh/*.pub), ANVIL (binary),
# ANVIL_PREBUILT=1 (skip cargo build), ANVIL_ACCEPT_TIMEOUT (per call, 900s).
set -euo pipefail

DRY=0 YES=0 CONTAINERS=0 BESZEL=0 PODMAN=0 CODING_AGENTS=0 HYGIENE=0 GREPTIMEDB=0 MONITORING=0 IN_USE=0 SANDBOX=0 TARGET=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run) DRY=1 ;;
    --yes) YES=1 ;;
    --containers) CONTAINERS=1 ;;
    --beszel) BESZEL=1 ;;
    --podman) PODMAN=1 ;;
    --coding-agents) CODING_AGENTS=1 ;;
    --hygiene) HYGIENE=1 ;;
    --greptimedb) GREPTIMEDB=1 ;;
    --monitoring) MONITORING=1 ;;
    --in-use) IN_USE=1 ;;
    --forgejo-sandbox) SANDBOX=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) [[ -z $TARGET ]] || { echo "one <user@host> only" >&2; exit 2; }; TARGET=$1 ;;
  esac
  shift
done
[[ $TARGET == ?*@?* ]] || { echo "usage: $0 [--dry-run] [--yes] [--containers] [--beszel] [--podman] [--coding-agents] [--hygiene [--greptimedb]] [--monitoring] [--in-use] [--forgejo-sandbox] <user@host>" >&2; exit 2; }
[[ $GREPTIMEDB == 0 || $HYGIENE == 1 ]] || { echo "--greptimedb needs --hygiene" >&2; exit 2; }
LOGIN=${TARGET%@*} HOST=${TARGET#*@}
OPS=ops NEW_PORT=2222
TIMEOUT=${ANVIL_ACCEPT_TIMEOUT:-900}

REPO=$(cd "$(dirname "$0")/.." && pwd)
ANVIL=${ANVIL:-"$REPO/target/release/anvil"}
TMPBASE=${TMPDIR:-/tmp}
WORK=$(mktemp -d "${TMPBASE%/}/anvil-accept.XXXXXX")
KNOWN_HOSTS="$WORK/known_hosts"
LIFELINE="$WORK/lifeline.sock"

# ---------------------------------------------------------------- helpers ---
say()  { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf 'acceptance: %s\n' "$*" >&2; exit 1; }

# quote <args...>: shell-quote for printing, bare when safe ('…' otherwise).
quote() {
  local a sq="'\\''"
  for a in "$@"; do
    if [[ $a =~ ^[A-Za-z0-9_./:=@%+,-]+$ ]]; then printf '%s ' "$a"
    else printf "'%s' " "${a//\'/$sq}"; fi
  done
}

# The only door to the host: every ssh and anvil invocation goes through run().
# --dry-run prints the argv and returns 0, so nothing reaches the host.
run() {
  local line w='$WORK' o='$SSH ' a='anvil '  # all three spelled out in preflight
  line=$(quote "$@")
  line=${line//"$(quote "${SSH_OPTS[@]}" -i "$PRIVKEY")"/"$o"}
  line=${line//"$ANVIL "/"$a"}
  printf '  + %s\n' "${line//"$WORK"/"$w"}" >&2
  [[ $DRY == 1 ]] && return 0
  "$@"
}
ff() { run "$ANVIL" "$@"; }

RESULTS=() FAILED=0 GATE_FAILED=0
# step <label> <fn...> — run, record PASS/FAIL, keep going.
step() {
  local label=$1; shift
  say "$label"
  local rc=0
  "$@" || rc=$?
  if [[ $DRY == 1 ]]; then RESULTS+=("DRY   $label")
  elif [[ $rc -eq 0 ]]; then RESULTS+=("PASS  $label")
  else RESULTS+=("FAIL  $label (exit $rc)"); FAILED=1; fi
}
# gate <label> <fn...> — like step, but a failure stops the run: everything
# after it assumes this reachability/state holds.
gate() {
  step "$@"
  [[ ${RESULTS[${#RESULTS[@]}-1]} != FAIL* ]] || { GATE_FAILED=1; exit 1; }
}

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes
          -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS")
rssh() { # rssh <user> <port> <remote command...> — a fresh connection (no mux)
  local user=$1 port=$2; shift 2
  run ssh "${SSH_OPTS[@]}" -i "$PRIVKEY" -o ControlMaster=no -o ControlPath=none -p "$port" "$user@$HOST" "$@"
}
rsudo() { # rsudo <user> <port> <script> — run a bash script as root on the host
  local user=$1 port=$2 script=$3
  local sudo=""; [[ $user == root ]] || sudo="sudo -n"
  if [[ $DRY == 1 ]]; then
    rssh "$user" "$port" "$sudo bash -euo pipefail -s"
    printf '%s\n' "$script" | sed 's/^/      | /' >&2
    return 0
  fi
  rssh "$user" "$port" "$sudo bash -euo pipefail -s" <<<"$script"
}
lifeline_open() { # a second session that survives sshd reloads; your way back in
  run ssh "${SSH_OPTS[@]}" -i "$PRIVKEY" -p "$2" -M -S "$LIFELINE" -o ControlPersist=yes -fN "$1@$HOST"
}
lifeline_close() { [[ -S $LIFELINE ]] || [[ $DRY == 1 && -n ${PRIVKEY:-} ]] || return 0; run ssh -q -S "$LIFELINE" -O exit "$HOST" || true; }

# host <user> <port> — point every fixture at this login (they include host.toml).
host() {
  note "host.toml -> $1@$HOST:$2"
  cat > "$WORK/host.toml" <<EOF
[host]
address = "$HOST"
user = "$1"
port = $2
identity_file = "$PRIVKEY"
ssh_options = ["UserKnownHostsFile=$KNOWN_HOSTS", "IdentitiesOnly=yes"]
EOF
  chmod 0600 "$WORK/host.toml"
}

# JSON assertions (smoke.sh's). In --dry-run there is no JSON: they pass.
show_modules() {
  [[ $DRY == 1 ]] && return 0
  jq -r '.[0].modules[] | [.status, .module, (.reason // .error // ((.reasons // []) | join("; ")))] | @tsv' "$1" \
    | awk -F'\t' '{ printf "  %-9s %-16s %s\n", $1, $2, $3 }'
}
assert_no_failures() {
  [[ $DRY == 1 ]] && return 0
  local bad
  bad=$(jq -r '[.[0].modules[] | select(.status == "failed" or .status == "skipped") | .module] | join(", ")' "$1")
  [[ -z $bad ]] || { note "failed/skipped: $bad"; return 1; }
}
assert_all_ok() {
  [[ $DRY == 1 ]] && return 0
  local bad
  bad=$(jq -r '[.[0].modules[] | select(.status != "ok") | "\(.module)=\(.status)"] | join(", ")' "$1")
  [[ -z $bad ]] || { note "not converged: $bad"; return 1; }
}
assert_status() { # assert_status <json> <module> <status>
  [[ $DRY == 1 ]] && return 0
  local got; got=$(jq -r --arg m "$2" '.[0].modules[] | select(.module == $m) | .status' "$1")
  [[ $got == "$3" ]] || { note "$2: expected $3, got ${got:-absent}"; return 1; }
}
want_rc() { [[ $DRY == 1 || $2 -eq $1 ]] || { note "expected exit $1, got $2"; return 1; }; }

# --------------------------------------------------------- anvil step fns ---
apply_ok() { # apply_ok <fixture> <tag>: converge; nothing failed or skipped
  ff apply -c "$WORK/$1" --output json --timeout "$TIMEOUT" > "$WORK/$2.json" || true
  show_modules "$WORK/$2.json"; assert_no_failures "$WORK/$2.json"
}
converged() { # converged <fixture> <tag>: re-apply all ok, check exit 0, diff empty
  local rc=0
  ff apply -c "$WORK/$1" --output json --timeout "$TIMEOUT" > "$WORK/$2-reapply.json" || true
  assert_no_failures "$WORK/$2-reapply.json" && assert_all_ok "$WORK/$2-reapply.json" || return 1
  ff check -c "$WORK/$1" --output json --timeout "$TIMEOUT" > "$WORK/$2-check.json" || rc=$?
  show_modules "$WORK/$2-check.json"; want_rc 0 "$rc" || return 1
  ff diff -c "$WORK/$1" --output json --timeout "$TIMEOUT" > "$WORK/$2-diff.json"
  [[ $DRY == 1 ]] && return 0
  local bad
  bad=$(jq -r '[.[0].files[]? | select(.change == "create" or .change == "modify") | .path] | join(", ")' "$WORK/$2-diff.json")
  [[ -z $bad ]] || { note "diff still wants to change: $bad"; return 1; }
}
rollback_only() { # rollback_only <fixture> <tag> <modules>
  ff rollback -c "$WORK/$1" --only "$3" --output json --timeout "$TIMEOUT" > "$WORK/$2.json" || true
  show_modules "$WORK/$2.json"; assert_no_failures "$WORK/$2.json"
}

CLEAN_EXIT=0
cleanup() {
  local rc=$?
  set +e
  if [[ $GATE_FAILED == 1 ]]; then
    echo
    echo "A reachability gate failed. The lifeline session (if it is still up) is your way in:"
    echo "  ssh -S $LIFELINE $HOST            # then: sudo -i"
    echo "Otherwise use the provider's console. Nothing was rolled back automatically."
  else
    lifeline_close
  fi
  echo
  echo "Results (JSON and configs in $WORK):"
  printf '  %s\n' "${RESULTS[@]:-"(no steps ran)"}"
  [[ $rc -eq 0 && $FAILED -eq 0 && $CLEAN_EXIT == 1 ]] && exit 0
  exit 1
}
trap cleanup EXIT

# --------------------------------------------------------------- preflight --
say "preflight (local)"
for tool in jq ssh; do command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"; done
if [[ $DRY == 0 && -z ${ANVIL_PREBUILT:-} ]]; then
  note "cargo build --release"
  (cd "$REPO" && cargo build --release --quiet)
fi
[[ $DRY == 1 || -x $ANVIL ]] || die "$ANVIL is not executable (set ANVIL=/path/to/anvil)"
PUBKEY=${ANVIL_ACCEPT_KEY:-}
if [[ -z $PUBKEY ]]; then
  for k in ~/.ssh/id_ed25519.pub ~/.ssh/*.pub; do [[ -f $k ]] && { PUBKEY=$k; break; }; done
fi
[[ -n $PUBKEY && -f $PUBKEY ]] || die "no public key found; set ANVIL_ACCEPT_KEY=~/.ssh/<key>.pub"
PRIVKEY=${PUBKEY%.pub}
[[ -f $PRIVKEY ]] || die "private key $PRIVKEY not found next to $PUBKEY"
ANVIL_ACCEPT_PUBKEY=$(cat "$PUBKEY"); export ANVIL_ACCEPT_PUBKEY
# podman-v2.toml: a throwaway "App key" (never a real App; minting fails).
ANVIL_ACCEPT_APP_KEY=$(openssl genrsa 2048 2>/dev/null); export ANVIL_ACCEPT_APP_KEY
[[ $LOGIN != "$OPS" ]] || die "log in as root or another sudo user, not '$OPS' (the script creates it)"
note "anvil: $ANVIL   key: $PUBKEY   target: $LOGIN@$HOST:22"
note "\$WORK = $WORK"
note "\$SSH  = $(quote "${SSH_OPTS[@]}" -i "$PRIVKEY")"

if [[ $IN_USE == 1 ]]; then
  :  # read-only: nothing to confirm
elif [[ $DRY == 0 && $YES == 0 && $SANDBOX == 1 ]]; then
  echo
  echo "This runs the Forgejo sandbox checks on $HOST: an ephemeral forgejo_runner (one sysbox sandbox), a throwaway"
  echo "repo on ${ANVIL_ACCEPT_FORGEJO_URL:-its own Forgejo behind Caddy (ACME, opens 80/443) on ${HOST//./-}.sslip.io} with one workflow;"
  echo "then rolls forgejo_runner back and deletes the repo (and its own Forgejo and Caddy)."
  read -r -p "Type the host ($HOST) to continue: " answer
  [[ $answer == "$HOST" ]] || die "not confirmed"
elif [[ $DRY == 0 && $YES == 0 && $MONITORING == 1 ]]; then
  echo
  echo "This runs the monitoring checks on $HOST: a temporary GreptimeDB (14000-14003, 2G) and Vector, a busybox"
  echo "container and a transient unit; then rolls greptimedb and vector back. dockerd is not touched."
  read -r -p "Type the host ($HOST) to continue: " answer
  [[ $answer == "$HOST" ]] || die "not confirmed"
elif [[ $DRY == 0 && $YES == 0 && $HYGIENE == 1 ]]; then
  echo
  echo "This runs the hygiene checks on $HOST: throwaway plugins, a busybox compose project or Quadlet"
  echo "(rolled back), a run of the forgejo-runner prune service$([[ $GREPTIMEDB == 1 ]] && echo ", a temporary GreptimeDB on 14000-14003")."
  read -r -p "Type the host ($HOST) to continue: " answer
  [[ $answer == "$HOST" ]] || die "not confirmed"
elif [[ $DRY == 0 && $YES == 0 && $CODING_AGENTS == 1 ]]; then
  echo
  echo "This adds the user 'agent', Claude Code and OpenCode to $HOST, then rolls coding_agents back."
  read -r -p "Type the host ($HOST) to continue: " answer
  [[ $answer == "$HOST" ]] || die "not confirmed"
elif [[ $DRY == 0 && $YES == 0 ]]; then
  echo
  echo "This hardens $HOST permanently (packages, users, sshd, ufw, a reboot)."
  echo "Use a disposable box only. See docs/design/acceptance.md."
  read -r -p "Type the host ($HOST) to continue: " answer
  [[ $answer == "$HOST" ]] || die "not confirmed"
fi

cp "$REPO"/scripts/acceptance/*.toml "$WORK/"
host "$LOGIN" 22
chmod 0600 "$WORK"/*.toml   # include trust: ours, not group/world-writable

# ------------------------------------------- --coding-agents only ---
# docs/design/coding-agents.md §9 checks 1, 2, 3, 7 (no setup), 8, 9, 10, as
# $LOGIN on a box that already runs other modules; nothing else is applied.
if [[ $CODING_AGENTS == 1 ]]; then
  CA_PORT=${ANVIL_ACCEPT_PORT:-22}
  host "$LOGIN" "$CA_PORT"
  ca_root() { rsudo "$LOGIN" "$CA_PORT" "$1"; }  # as root; agent-side checks use runuser
  ca_validate() { local f; for f in coding-agents coding-agents-edit coding-agents-docker; do ff validate -c "$WORK/$f.toml" >/dev/null || return 1; done; }
  step "validate coding-agents fixtures (local)" ca_validate
  gate "doctor ($LOGIN@$CA_PORT)" ff doctor -c "$WORK/coding-agents.toml" --timeout 60
  # What was here before, so rollback is judged against it.
  CA_HAD_CLAUDE=0 CA_HAD_OPENCODE=0 CA_HAD_SUBIDS=0
  ca_has() { ca_root "h=\$(getent passwd agent | cut -d: -f6); [ -n \"\$h\" ] && test -e \"\$h/$1\""; }
  ca_pre() {
    if ca_has .local/bin/claude; then [[ $DRY == 1 ]] || CA_HAD_CLAUDE=1; fi
    if ca_has .opencode/bin/opencode; then [[ $DRY == 1 ]] || CA_HAD_OPENCODE=1; fi
    note "before: agent's claude=$CA_HAD_CLAUDE, opencode=$CA_HAD_OPENCODE"
  }
  step "record the agent's pre-existing claude/opencode" ca_pre

  # 1. Apply, then idempotent (both agents self-update: no version drift).
  gate "1. apply coding-agents" apply_ok coding-agents.toml ca
  step "1. idempotent: re-apply ok, check 0, diff empty" converged coding-agents.toml ca

  # 2 + 3. Both agents run for the agent, from its home.
  CA_VERSIONS=$(cat <<'CAEOF'
h=$(getent passwd agent | cut -d: -f6) rc=0
as() { runuser -u agent -- env -i HOME="$h" PATH="$h/.local/bin:$h/.opencode/bin:/usr/local/bin:/usr/bin:/bin" "$@" </dev/null; }
for bin in claude opencode; do
  err=$(mktemp)
  if ! v=$(as "$bin" --version 2>"$err"); then
    echo "FAIL: $bin --version as agent:"; sed 's/^/  /' "$err"; rc=1
  else
    echo "$bin $v at $(as bash -c "command -v $bin")"
  fi
  rm -f "$err"
done
[ "$(as bash -c 'command -v claude')" = "$h/.local/bin/claude" ] || { echo "FAIL: claude not in ~/.local/bin"; rc=1; }
[ "$(as bash -c 'command -v opencode')" = "$h/.local/bin/opencode" ] || { echo "FAIL: opencode not linked in ~/.local/bin"; rc=1; }
runuser -u agent -- bash -lc 'command -v opencode' >/dev/null || { echo "FAIL: opencode not on a login shell's PATH"; rc=1; }
want=$(curl -fsSL https://downloads.claude.ai/claude-code-releases/stable)
got=$(as claude --version 2>/dev/null | awk '{print $1}')
echo "claude $got, stable channel now $want (equal unless it moved since install)"; [ "$got" = "$want" ] || rc=1
if dpkg -s claude-code >/dev/null 2>&1; then echo "FAIL: apt claude-code installed"; rc=1; fi
exit $rc
CAEOF
)
  step "2+3. claude (stable) and opencode run for the agent from its home; no apt" ca_root "$CA_VERSIONS"

  # 2. Node 24 from NodeSource for the agent; context-mode's doctor (over MCP
  # stdio, the fixture's opencode_mcp argv) passes D2; D3 is reported.
  CA_NODE=$(cat <<'CAEOF'
h=$(getent passwd agent | cut -d: -f6) rc=0
as() { runuser -u agent -- env -i HOME="$h" PATH="$h/.local/bin:$h/.opencode/bin:/usr/local/bin:/usr/bin:/bin" "$@"; }
v=$(as node --version </dev/null 2>/dev/null | sed 's/^v//')
echo "node $v at $(as bash -c 'command -v node' </dev/null), package $(dpkg-query -W -f='${Version}' nodejs)"
dpkg --compare-versions "$v" ge 24.15.0 || { echo "FAIL: node $v < 24.15.0"; rc=1; }
[ "$(as bash -c 'command -v node' </dev/null)" = /usr/bin/node ] || { echo "FAIL: node is not /usr/bin/node"; rc=1; }
dpkg-query -W -f='${Version}' nodejs | grep -q nodesource || { echo "FAIL: nodejs not from NodeSource"; rc=1; }
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"anvil-acceptance","version":"1"}}}'
inited='{"jsonrpc":"2.0","method":"notifications/initialized"}'
call='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ctx_doctor","arguments":{}}}'
out=$(mktemp)
# stdin stays open until the reply; the server exits when the pipe closes.
( printf '%s\n%s\n%s\n' "$init" "$inited" "$call"; sleep 60 ) \
  | ( cd "$h" && timeout 90 runuser -u agent -- env -i HOME="$h" PATH="$h/.local/bin:/usr/bin:/bin" \
      npx -y context-mode@next server --agent opencode ) > "$out" 2>/dev/null || true
rows=$(python3 -c '
import json, sys
for line in open(sys.argv[1]):
    try: m = json.loads(line)
    except ValueError: continue
    if m.get("id") == 2:
        for c in (m.get("result") or {}).get("content", []):
            print(c.get("text", ""))
' "$out")
rm -f "$out"
d2=$(printf '%s\n' "$rows" | grep -E '\bD2\b' || true)
d3=$(printf '%s\n' "$rows" | grep -E '\bD3\b' || true)
echo "ctx_doctor D2: ${d2:-<missing>}"
echo "ctx_doctor D3: ${d3:-<missing>}"
if [ -z "$d2" ] || printf '%s' "$d2" | grep -q FAIL; then echo "FAIL: ctx_doctor D2 node"; rc=1; fi
exit $rc
CAEOF
)
  step "2. node >= 24.15 from NodeSource; context-mode doctor D2 node passes (D3 shown)" ca_root "$CA_NODE"

  # 7. Lists, marker; re-run only on a list edit (the idempotent step above
  # proved a re-apply does not re-run).
  CA_LISTS=$(cat <<'CAEOF'
h=$(getent passwd agent | cut -d: -f6) rc=0
as() { runuser -u agent -- env -i HOME="$h" PATH="$h/.local/bin:$h/.opencode/bin:/usr/local/bin:/usr/bin:/bin" "$@" </dev/null; }
chk() { if as "$@" >/dev/null 2>&1; then echo "ok: $*"; else echo "FAIL: $*"; rc=1; fi; }
chk test -e "$h/.agents/skills/find-skills"
chk test -e "$h/.agents/skills/frontend-design"
chk test -e "$h/.claude/skills/find-skills"
if as test -e "$h/.claude/skills/frontend-design"; then echo "FAIL: OpenCode-only skill in ~/.claude/skills"; rc=1; fi
chk bash -c 'claude plugin list 2>/dev/null | grep -q commit-commands || grep -rqs commit-commands ~/.claude/plugins'
chk grep -rqs ponytail "$h/.config/opencode"
# OpenCode v2 reads mcp.<name>; mcp.servers is what `opencode mcp add` wrote.
chk python3 -c 'import json, os, sys; m = json.load(open(os.path.expanduser("~/.config/opencode/opencode.json"))).get("mcp", {}); sys.exit("context-mode" not in m or "servers" in m)'
chk test -s "$h/.agents/.anvil-coding-agents"
exit $rc
CAEOF
)
  step "7. skills, plugin, OpenCode plugin + MCP, marker" ca_root "$CA_LISTS"
  ca_edit() {
    ff apply -c "$WORK/coding-agents-edit.toml" --output json --timeout "$TIMEOUT" > "$WORK/ca-edit.json" || true
    show_modules "$WORK/ca-edit.json"
    assert_status "$WORK/ca-edit.json" coding_agents changed || return 1
    apply_ok coding-agents.toml ca-back || return 1
    assert_status "$WORK/ca-back.json" coding_agents changed
  }
  step "7. editing a list re-runs the installers (and back)" ca_edit

  # 8. What the agent can't reach.
  CA_REACH=$(cat <<'CAEOF'
u=agent rc=0
h=$(getent passwd $u | cut -d: -f6)
as() { runuser -u $u -- "$@" </dev/null >/dev/null 2>&1; }
if as sudo -n true; then echo "FAIL: sudo -n true works"; rc=1; else echo "ok: no sudo"; fi
for f in /etc/anvil/github-runner/app.pem /var/run/docker.sock /run/podman/podman.sock \
         $(find /opt/github-runner /var/lib/github-runner /var/lib/forgejo-runner /etc/forgejo-runner \
                -maxdepth 4 \( -name '.credentials*' -o -name '.runner' -o -name 'config.yml' \) 2>/dev/null); do
  [ -e "$f" ] || continue
  if as test -r "$f"; then echo "FAIL: can read $f"; rc=1; else echo "ok: can't read $f"; fi
done
for d in /root /home/* /opt/github-runner /var/lib/github-runner /var/lib/forgejo-runner; do
  [ -d "$d" ] && [ "$d" != "$h" ] || continue
  if as ls "$d"; then echo "FAIL: can list $d"; rc=1; else echo "ok: can't list $d"; fi
done
j=$(runuser -u $u -- journalctl --system -q -n 20 --no-pager 2>/dev/null || true)
if [ -n "$j" ]; then echo "FAIL: journalctl shows the system journal"; rc=1; else echo "ok: no system journal"; fi
exit $rc
CAEOF
)
  step "8. agent: no sudo; secrets, homes, sockets, journal out of reach" ca_root "$CA_REACH"

  # 9. Caps on user-<uid>.slice; spawning past tasks_max is refused.
  CA_CAPS=$(cat <<'CAEOF'
U=$(id -u agent)
systemctl show "user-$U.slice" -p TasksMax -p MemoryMax -p CPUQuotaPerSecUSec | tee /dev/stderr \
  | sort | tr '\n' ' ' | grep -q 'CPUQuotaPerSecUSec=2s MemoryMax=4294967296 TasksMax=512'
cg=/sys/fs/cgroup/user.slice/user-$U.slice
before=$(awk '/^max /{print $2}' "$cg/pids.events")
systemctl stop anvil-accept-forks 2>/dev/null || true; systemctl reset-failed anvil-accept-forks 2>/dev/null || true
systemd-run --quiet --collect --unit=anvil-accept-forks --uid=agent --slice="user-$U.slice" \
  bash -c 'for i in $(seq 700); do sleep 60 & done 2>/dev/null; wait'
sleep 20
after=$(awk '/^max /{print $2}' "$cg/pids.events") cur=$(cat "$cg/pids.current")
systemctl stop anvil-accept-forks 2>/dev/null || true
echo "pids.current=$cur (max 512), refused forks: $before -> $after"
[ "$cur" -le 512 ] && [ "$after" -gt "$before" ]
CAEOF
)
  ca_caps() {
    ca_root "$CA_CAPS" || return 1
    rssh "$LOGIN" "$CA_PORT" true   # a fresh login still works
  }
  step "9. caps: slice limits, spawning stops at tasks_max, sshd answers" ca_caps

  # 11. docker = "rootless": the host's engine as the agent, from a login shell.
  CA_DOCKER=$(cat <<'CAEOF'
U=$(id -u agent) rc=0
as() { runuser -l agent -c "$1" </dev/null 2>&1; }
host=$(as 'printf %s "$DOCKER_HOST"')
case $host in (unix:///run/user/$U/*) echo "ok: DOCKER_HOST=$host" ;; (*) echo "FAIL: DOCKER_HOST=$host"; rc=1 ;; esac
if as 'docker info' | grep -qi rootless; then echo "ok: engine reports rootless"; else echo "FAIL: docker info not rootless"; rc=1; fi
if out=$(as 'docker run --rm busybox id -u'); then echo "ok: docker run as agent ($out)"; else echo "FAIL: docker run: $out"; rc=1; fi
if as 'docker run --rm -v /etc:/h:ro busybox cat /h/shadow' >/dev/null; then echo "FAIL: container root read /etc/shadow"; rc=1
else echo "ok: container root can't read /etc/shadow"; fi
exit $rc
CAEOF
)
  ca_docker() {
    # useradd usually gives the agent a range already; rollback keeps one anvil didn't add.
    if ca_root "grep -q '^agent:' /etc/subuid"; then [[ $DRY == 1 ]] || CA_HAD_SUBIDS=1; fi
    apply_ok coding-agents-docker.toml ca-docker || return 1
    ca_root "$CA_DOCKER"
  }
  step "11. docker = rootless: DOCKER_HOST, docker run as the agent, container root is not host root" ca_docker

  # 10. Rollback: installs gone, home kept.
  ca_rollback() {
    rollback_only coding-agents-docker.toml ca-rollback coding_agents || return 1
    ca_root "had_claude=$CA_HAD_CLAUDE had_opencode=$CA_HAD_OPENCODE had_subids=$CA_HAD_SUBIDS
$(cat <<'CAEOF'
U=$(id -u agent) h=$(getent passwd agent | cut -d: -f6) rc=0
gone() { if [ -e "$1" ]; then echo "FAIL: $1 still there"; rc=1; else echo "ok: $1 gone"; fi; }
gone /var/lib/systemd/linger/agent; gone "/etc/systemd/system/user-$U.slice.d/99-anvil-coding-agents.conf"
gone /etc/systemd/user/anvil-docker-rootless.service
if grep -q '^agent:' /etc/subuid; then
  if [ "$had_subids" = 1 ]; then echo "ok: agent's own subordinate ids kept"; else echo "FAIL: agent's subordinate ids kept"; rc=1; fi
elif [ "$had_subids" = 1 ]; then echo "FAIL: agent's pre-existing subordinate ids removed"; rc=1
else echo "ok: agent's subordinate ids gone"; fi
gone "$h/.agents/.anvil-coding-agents"
gone /etc/apt/keyrings/nodesource.asc; gone /etc/apt/sources.list.d/nodesource.list; gone /etc/apt/preferences.d/99-anvil-nodesource
if [ -x /usr/bin/node ]; then echo "ok: nodejs kept"; else echo "FAIL: /usr/bin/node gone"; rc=1; fi
[ "$had_claude" = 1 ] || { gone "$h/.local/bin/claude"; gone "$h/.local/share/claude"; }
[ "$had_opencode" = 1 ] || { gone "$h/.opencode/bin"; gone "$h/.local/bin/opencode"; }
if runuser -u agent -- test -e "$h/.agents/skills/find-skills" -a -d "$h/.claude"; then echo "ok: home data kept (~/.agents, ~/.claude)"; else echo "FAIL: home data gone"; rc=1; fi
exit $rc
CAEOF
)"
  }
  step "10. rollback: agent binaries, linger, drop-in, rootless engine, NodeSource source gone; config, data, nodejs kept" ca_rollback
  CLEAN_EXIT=1
  exit 0
fi

# ------------------------------------------------ --hygiene only ---
# docs/design/acceptance.md "--hygiene": fixes 3-6 (and 1 with --greptimedb)
# as $LOGIN on a box that already runs Forgejo and runners. Applies only
# its own fixtures, each with --only, and rolls them back.
if [[ $HYGIENE == 1 ]]; then
  HY_PORT=${ANVIL_ACCEPT_PORT:-22}
  host "$LOGIN" "$HY_PORT"
  hy_root() { rsudo "$LOGIN" "$HY_PORT" "$1"; }
  # Plugins from a private XDG dir: one converged, one that changes, one that
  # fails after stderr noise (what needrestart prints).
  export XDG_CONFIG_HOME="$WORK/xdg"
  hy_plugin() { # <name> <apply.sh> [check.sh]
    local d="$XDG_CONFIG_HOME/anvil/plugins/$1"
    (umask 022; mkdir -p "$d")
    printf 'name = "%s"\nsection = "%s"\n' "$1" "${1//-/_}" > "$d/plugin.toml"
    printf '%s\n' "$2" > "$d/apply.sh"
    [[ -z ${3:-} ]] || printf '%s\n' "$3" > "$d/check.sh"
    printf 'include = ["host.toml"]\n[%s]\n' "${1//-/_}" > "$WORK/$1.toml"
    chmod 0600 "$WORK/$1.toml"
  }
  hy_plugin hygiene-ok 'true' 'true'
  hy_plugin hygiene-change 'true' 'false'
  hy_plugin hygiene-fail "echo 'Scanning processes... (noise)' >&2; printf 'FAILED: hygiene: planted failure\n' >&2; exit 1"
  gate "doctor ($LOGIN@$HY_PORT)" ff doctor -c "$WORK/hygiene-ok.toml" --timeout 60
  HY_RUNS=/var/lib/anvil/runs
  hy_clean_runs() { hy_root "rm -f $HY_RUNS/plugin::hygiene-*"; }

  # 5. Run manifests: none for a converged apply, kept (with its line) for a change.
  hy_manifests() {
    hy_clean_runs || return 1
    ff apply -c "$WORK/hygiene-ok.toml" --no-check --output json > "$WORK/hy-ok.json" || return 1
    ff apply -c "$WORK/hygiene-change.toml" --output json > "$WORK/hy-change.json" || return 1
    assert_status "$WORK/hy-change.json" plugin::hygiene-change changed || return 1
    hy_root "set +o pipefail
ok=\$(ls $HY_RUNS/plugin::hygiene-ok.* 2>/dev/null | wc -l); ch=\$(cat $HY_RUNS/plugin::hygiene-change.* 2>/dev/null)
echo \"converged run: \$ok manifest(s); changed run: \$ch\"
echo \"empty manifests left by older applies: \$(find $HY_RUNS -maxdepth 1 -type f -empty | wc -l)\"
[ \"\$ok\" = 0 ] && printf '%s' \"\$ch\" | grep -q '^cmd'"
  }
  step "5. run manifests: none for a converged apply, kept for a change" hy_manifests

  # 6. The report names the FAILED: line, not the noise before it.
  hy_report() {
    local rc=0 got
    ff apply -c "$WORK/hygiene-fail.toml" --output json > "$WORK/hy-fail.json" || rc=$?
    want_rc 1 "$rc" || return 1
    [[ $DRY == 1 ]] && return 0
    got=$(jq -r '.[0].modules[] | select(.module == "plugin::hygiene-fail") | .reason' "$WORK/hy-fail.json")
    note "reason: $got"
    [[ $got == "FAILED: hygiene: planted failure" ]]
  }
  step "6. apply report shows the FAILED: line" hy_report
  step "5/6. remove the plugin manifests" hy_clean_runs

  # 3. Superseded images: a busybox project moves 1.36 -> 1.37; 1.36 goes,
  # 1.35 (a stopped container's) and 1.37 stay; check is aligned.
  HY_ENGINE=docker
  hy_engine() {
    local e
    e=$(rssh "$LOGIN" "$HY_PORT" 'if systemctl is-active --quiet docker; then echo docker; elif command -v podman >/dev/null; then echo podman; else echo none; fi') || return 1
    [[ $DRY == 1 ]] || HY_ENGINE=$e
    note "engine: $HY_ENGINE"
    [[ $HY_ENGINE != none ]]
  }
  gate "3. host engine" hy_engine
  hy_images_fixture() { # <tag>
    if [[ $HY_ENGINE == podman ]]; then
      printf 'include = ["host.toml"]\n[podman]\n[containers]\nruntime = "podman"\n[containers.quadlet.hygiene]\ncontent = """\n[Container]\nImage=docker.io/library/busybox:%s\nExec=sleep 2147483647\n"""\n' "$1"
    else
      printf 'include = ["host.toml"]\n[containers.compose.hygiene]\ncontent = """\nservices:\n  idle:\n    image: docker.io/library/busybox:%s\n    command: ["sleep", "2147483647"]\n"""\n' "$1"
    fi > "$WORK/hygiene-images.toml"
    chmod 0600 "$WORK/hygiene-images.toml"
  }
  hy_images() {
    local e=$HY_ENGINE
    hy_root "$e pull -q docker.io/library/busybox:1.35 >/dev/null; { $e rm -f anvil-hygiene-keep >/dev/null 2>&1 || true; }; $e create --name anvil-hygiene-keep docker.io/library/busybox:1.35 true >/dev/null" || return 1
    hy_images_fixture 1.36
    ff apply -c "$WORK/hygiene-images.toml" --only containers --output json > "$WORK/hy-img1.json" || true
    assert_no_failures "$WORK/hy-img1.json" || return 1
    hy_images_fixture 1.37
    ff apply -c "$WORK/hygiene-images.toml" --only containers --output json > "$WORK/hy-img2.json" || true
    show_modules "$WORK/hy-img2.json"; assert_no_failures "$WORK/hy-img2.json" || return 1
    ff check -c "$WORK/hygiene-images.toml" --only containers --output json > "$WORK/hy-img-check.json" || { note "check not aligned"; show_modules "$WORK/hy-img-check.json"; return 1; }
    hy_root "rc=0; b=docker.io/library/busybox
$e image ls \$b --format '{{.Repository}}:{{.Tag}}'
! $e image inspect \$b:1.36 >/dev/null 2>&1 || { echo 'FAIL: 1.36 still there'; rc=1; }
$e image inspect \$b:1.35 >/dev/null 2>&1 || { echo 'FAIL: 1.35 (stopped container) removed'; rc=1; }
$e image inspect \$b:1.37 >/dev/null 2>&1 || { echo 'FAIL: 1.37 missing'; rc=1; }
exit \$rc"
  }
  step "3. superseded image removed after pull + recreate; used and current kept; check aligned" hy_images
  hy_images_cleanup() {
    rollback_only hygiene-images.toml hy-img-rollback containers || return 1
    hy_root "$HY_ENGINE rm -f anvil-hygiene-keep >/dev/null 2>&1 || true; for i in 1.35 1.37; do $HY_ENGINE image rm docker.io/library/busybox:\$i >/dev/null 2>&1 || true; done"
  }
  step "3. rollback the busybox project, remove its images" hy_images_cleanup

  # 4. forgejo_runner prune: timer on, the service runs, and its script (on a
  # scratch HOME, so the real caches stay) wipes caches past the cap when idle.
  HY_PRUNE=$(cat <<'HYEOF'
s=/usr/local/libexec/anvil/forgejo-runner-prune.sh h=/var/lib/forgejo-runner
[ -e "$s" ] || { echo "no forgejo_runner prune script: apply this build with the host's config first"; exit 1; }
systemctl is-enabled --quiet anvil-forgejo-runner-prune.timer || { echo "FAIL: timer not enabled"; exit 1; }
systemctl start anvil-forgejo-runner-prune.service || { journalctl -u anvil-forgejo-runner-prune -n 20 --no-pager; exit 1; }
max=$(grep -o -- '-gt [0-9]*' "$s" | head -n1 | cut -d' ' -f2)
t=$h/.anvil-hygiene; rm -rf "$t"
runuser -u forgejo-runner -- mkdir -p "$t/.cache"
runuser -u forgejo-runner -- truncate -s $((max + 1073741824)) "$t/.cache/sparse"
sed "s#'$h/#'$t/#g" "$s" > /tmp/anvil-hygiene-prune.sh; chmod 0644 /tmp/anvil-hygiene-prune.sh
if runuser -u forgejo-runner -- bash -c "$(sed -n '/^idle()/,/^}/p' "$s"); idle"; then idle=1; else idle=0; fi
runuser -u forgejo-runner -- bash /tmp/anvil-hygiene-prune.sh  # /tmp is noexec under CIS
rm -f /tmp/anvil-hygiene-prune.sh
if [ -e "$t/.cache/sparse" ]; then left=1; else left=0; fi
rm -rf "$t"
echo "cap $max bytes, runner idle=$idle, sparse cache left=$left"
[ "$idle" = 1 ] || { echo "a job is running: re-run when the runner is idle"; exit 1; }
[ "$left" = 0 ]
HYEOF
)
  step "4. forgejo_runner prune timer enabled; caches past the cap wiped while idle" hy_root "$HY_PRUNE"

  # 1. (--greptimedb) retention: a temporary GreptimeDB with a 7d TTL.
  if [[ $GREPTIMEDB == 1 ]]; then
    HY_GT_VERSION=${ANVIL_ACCEPT_GREPTIMEDB_VERSION:-v0.12.0}
    { printf 'include = ["host.toml"]\n'
      [[ $HY_ENGINE != podman ]] || printf '[podman]\n'
      printf '[greptimedb]\nversion = "%s"\nretention = "7d"\nhttp_port = 14000\ngrpc_port = 14001\nmysql_port = 14002\npostgres_port = 14003\ndata_dir = "/var/lib/anvil-hygiene-greptimedb"\n' "$HY_GT_VERSION"
    } > "$WORK/hygiene-greptimedb.toml"
    chmod 0600 "$WORK/hygiene-greptimedb.toml"
    hy_gt_free() {
      hy_root "! $HY_ENGINE container inspect greptimedb >/dev/null 2>&1 || { echo 'a greptimedb container already runs here: skipping'; exit 1; }"
    }
    gate "1. no greptimedb on the host yet" hy_gt_free
    hy_gt_apply() {
      ff apply -c "$WORK/hygiene-greptimedb.toml" --only greptimedb --output json --timeout "$TIMEOUT" > "$WORK/hy-gt.json" || true
      show_modules "$WORK/hy-gt.json"; assert_no_failures "$WORK/hy-gt.json"
    }
    step "1. apply greptimedb $HY_GT_VERSION with retention = 7d (--only)" hy_gt_apply
    step "1. greptimedb aligned (check --only)" ff check -c "$WORK/hygiene-greptimedb.toml" --only greptimedb
    step "1. database public has the 7d TTL" rssh "$LOGIN" "$HY_PORT" \
      "curl -fsS -X POST http://127.0.0.1:14000/v1/sql --data-urlencode 'sql=SHOW CREATE DATABASE public' | tee /dev/stderr | grep -iqE 'ttl[^0-9]*(7d|7 ?days|1week)'"
    hy_gt_cleanup() {
      rollback_only hygiene-greptimedb.toml hy-gt-rollback greptimedb || return 1
      hy_root "rm -rf /var/lib/anvil-hygiene-greptimedb; for i in docker.io/greptime/greptimedb greptime/greptimedb; do $HY_ENGINE image rm \$i:$HY_GT_VERSION >/dev/null 2>&1 || true; done"
    }
    step "1. rollback greptimedb, remove its data and image" hy_gt_cleanup
  fi
  CLEAN_EXIT=1
  exit 0
fi

# ------------------------------------------ --in-use (read-only follow-ups) ---
# docs/design/acceptance.md "--in-use": read-only, as $LOGIN on a Docker host
# that already runs the real config (Forgejo compose, Vector, sysbox).
if [[ $IN_USE == 1 ]]; then
  IU_PORT=${ANVIL_ACCEPT_PORT:-22}
  host "$LOGIN" "$IU_PORT"
  iu_root() { rsudo "$LOGIN" "$IU_PORT" "$1"; }
  printf 'include = ["host.toml"]\n[docker]\nuserns_remap = false\niptables_off = false\nlive_restore = false\n' > "$WORK/in-use-explicit.toml"
  printf 'include = ["host.toml"]\n[docker]\n' > "$WORK/in-use-defaulted.toml"
  chmod 0600 "$WORK"/in-use-*.toml
  gate "doctor ($LOGIN@$IU_PORT)" ff doctor -c "$WORK/in-use-explicit.toml" --timeout 60
  iu_check() { # <fixture> <want: failed|not-failed>
    ff check -c "$WORK/$1" --only docker --output json --timeout "$TIMEOUT" > "$WORK/$1.json" || true
    show_modules "$WORK/$1.json"
    [[ $DRY == 1 ]] && return 0
    local d; d=$(jq -r '.[0].modules[] | select(.module == "docker") | "\(.status) \(.error // "")"' "$WORK/$1.json")
    note "docker: $d"
    if [[ $2 == failed ]]; then [[ $d == failed* && $d == *userns_remap* ]]; else [[ $d != failed* ]]; fi
  }
  step "1. explicit userns_remap = false: check --only docker, no userns flip" iu_check in-use-explicit.toml not-failed
  step "1. defaulted [docker] on this host (images present): FAILED, names userns_remap" iu_check in-use-defaulted.toml failed
  step "2. Forgejo compose logs with the daemon's driver (no logging: block)" iu_root "docker container inspect forgejo >/dev/null 2>&1 || { echo 'skip: no forgejo container'; exit 0; }
! grep -q '^ *logging:' /etc/forgejo/compose.yaml || { echo 'FAIL: compose.yaml sets logging:'; exit 1; }
want=\$(docker info -f '{{.LoggingDriver}}'); got=\$(docker inspect -f '{{.HostConfig.LogConfig.Type}}' forgejo)
echo \"daemon: \$want, forgejo: \$got\"; [ \"\$want\" = \"\$got\" ]"
  # Polls 10 min for a row Vector shipped since its start (pipeline flows),
  # then: none of them is sysbox-fs's reaper line, though the journal has it.
  step "3. Vector drops sysbox-fs's 'reaper: nothing to reap', ships the rest" iu_root "set +o pipefail
c=/etc/vector/vector.toml; [ -f \$c ] || { echo 'skip: no vector config'; exit 0; }
grep -q 'reaper: nothing to reap' \$c || { echo 'FAIL: no sysbox-fs filter in vector.toml'; exit 1; }
systemctl is-active --quiet vector || { echo 'FAIL: vector inactive'; exit 1; }
systemctl cat sysbox-fs >/dev/null 2>&1 || { echo 'skip: no sysbox-fs'; exit 0; }
sql=\$(grep -m1 -o 'http://[^\"]*' \$c)/v1/sql
t=\$(date -u -d \"\$(systemctl show -p ActiveEnterTimestamp --value vector)\" '+%Y-%m-%d %H:%M:%S')
n() { curl -fsS -X POST \$sql --data-urlencode \"sql=SELECT count(*) FROM vector_logs WHERE greptime_timestamp > '\$t'\$1\" | grep -o '\"rows\":\\[\\[[0-9]*' | grep -o '[0-9]*\$'; }
for i in \$(seq 1 120); do [ \"\$(n '' || echo 0)\" -gt 0 ] && break; sleep 5; done
[ \"\$(n '' || echo 0)\" -gt 0 ] || { echo \"FAIL: nothing shipped since \$t\"; exit 1; }
j=\$(journalctl -u sysbox-fs --since \"\$t UTC\" --no-pager | grep -c 'reaper: nothing to reap' || true)
r=\$(n \" AND \\\"_SYSTEMD_UNIT\\\" = 'sysbox-fs.service' AND message LIKE '%reaper: nothing to reap%'\" || true)
echo \"since \$t: journal \$j reaper line(s), vector_logs \${r:-?}\"; [ \"\$r\" = 0 ]"
  CLEAN_EXIT=1
  exit 0
fi

# --------------------------------------------- --monitoring only ---
# docs/design/acceptance.md "--monitoring": as $LOGIN on a Docker host in use
# (Forgejo, runners, agents keep running). Applies only greptimedb + vector
# with --only (daemon.json and dockerd are never touched: the container line
# uses a per-container journald driver) and rolls them back.
if [[ $MONITORING == 1 ]]; then
  MO_PORT=${ANVIL_ACCEPT_PORT:-22}
  host "$LOGIN" "$MO_PORT"
  mo_root() { rsudo "$LOGIN" "$MO_PORT" "$1"; }
  MO_SQL=http://127.0.0.1:14000/v1/sql MO_DATA=/var/lib/anvil-monitoring-greptimedb
  MO_TAG=$(date +%s) MO_CTR=anvil-monitoring-probe MO_IMG=docker.io/library/busybox:1.37
  printf 'include = ["host.toml"]\n[greptimedb]\nretention = "7d"\nmemory_max = "2G"\nhttp_port = 14000\ngrpc_port = 14001\nmysql_port = 14002\npostgres_port = 14003\ndata_dir = "%s"\n[vector]\ngreptimedb_http_port = 14000\ngreptimedb_grpc_port = 14001\nscrape_interval_secs = 5\n' "$MO_DATA" > "$WORK/monitoring.toml"
  chmod 0600 "$WORK/monitoring.toml"
  gate "doctor ($LOGIN@$MO_PORT)" ff doctor -c "$WORK/monitoring.toml" --timeout 60
  mo_free() {
    mo_root "systemctl is-active --quiet docker || { echo 'not a Docker host'; exit 1; }
! docker container inspect greptimedb >/dev/null 2>&1 || { echo 'a greptimedb container already runs here'; exit 1; }
[ ! -e /etc/vector/vector.toml ] || { echo 'vector is already configured here'; exit 1; }"
  }
  gate "0. Docker host, no greptimedb container, no vector config yet" mo_free
  mo_apply() {
    ff apply -c "$WORK/monitoring.toml" --only greptimedb,vector --output json --timeout "$TIMEOUT" > "$WORK/mo-apply.json" || true
    show_modules "$WORK/mo-apply.json"; assert_no_failures "$WORK/mo-apply.json"
  }
  gate "1. apply greptimedb (default version, retention 7d, memory_max 2G) + vector (--only)" mo_apply
  step "1. greptimedb + vector aligned (check --only)" ff check -c "$WORK/monitoring.toml" --only greptimedb,vector
  step "2. TTL 7d on public, container memory capped at 2G" mo_root "set +o pipefail
curl -fsS -X POST $MO_SQL --data-urlencode 'sql=SHOW CREATE DATABASE public' | grep -iqE 'ttl[^0-9]*(7d|7 ?days|1week)' || { echo 'FAIL: no 7d TTL'; exit 1; }
m=\$(docker inspect -f '{{.HostConfig.Memory}}' greptimedb); echo \"memory limit: \$m\"; [ \"\$m\" = 2147483648 ]"
  step "2. the four dashboards are imported" mo_root "set +o pipefail
d=\$(curl -fsS http://127.0.0.1:14000/v1/dashboards); rc=0
for n in anvil-host anvil-errors anvil-containers anvil-ci; do
  printf '%s' \"\$d\" | grep -q \"\\\"\$n\\\"\" && echo \"ok: \$n\" || { echo \"FAIL: \$n missing\"; rc=1; }
done; exit \$rc"

  # Poll SQL until a count is > 0. Vector first ships the retained journal,
  # so new lines can take minutes on a host with history.
  mo_poll() { # <label> <sql>
    mo_root "set +o pipefail
for i in \$(seq 1 120); do
  n=\$(curl -fsS -X POST $MO_SQL --data-urlencode $(quote "sql=$2") 2>/dev/null | grep -o '\"rows\":\[\[[0-9]*' | grep -o '[0-9]*\$' || true)
  [ \"\${n:-0}\" -gt 0 ] && { echo \"$1: \$n row(s)\"; exit 0; }; sleep 5
done; echo \"FAIL: $1: nothing after 10 min\"; exit 1"
  }
  step "3. a transient unit's journald line arrives" mo_root "systemd-run --quiet --wait --unit=anvil-monitoring-$MO_TAG echo anvil-monitoring-unit-$MO_TAG"
  step "3. ... in vector_logs with its _SYSTEMD_UNIT" mo_poll "unit line" \
    "SELECT count(*) FROM vector_logs WHERE message = 'anvil-monitoring-unit-$MO_TAG' AND \"_SYSTEMD_UNIT\" = 'anvil-monitoring-$MO_TAG.service'"
  MO_ID=""
  mo_ctr() {
    local out
    out=$(mo_root "docker rm -f $MO_CTR >/dev/null 2>&1 || true
docker run -d --name $MO_CTR --log-driver=journald $MO_IMG sh -c 'echo anvil-monitoring-ctr-$MO_TAG; sleep 600'") || return 1
    [[ $DRY == 1 ]] || MO_ID=$(tail -n1 <<<"$out")
    note "container id: ${MO_ID:-<id>}"
  }
  step "4. a container with the journald log driver (dockerd untouched)" mo_ctr
  step "4. ... its line arrives with CONTAINER_NAME" mo_poll "container line" \
    "SELECT count(*) FROM vector_logs WHERE message = 'anvil-monitoring-ctr-$MO_TAG' AND \"CONTAINER_NAME\" = '$MO_CTR'"
  step "5. cgroup CPU metrics for the container" mo_poll "container cgroup" \
    "SELECT count(*) FROM host_cgroup_cpu_usage_seconds_total WHERE cgroup = 'system.slice/docker-${MO_ID:-<id>}.scope'"
  step "5. cgroup CPU metrics for ci.slice" mo_poll "ci.slice" \
    "SELECT count(*) FROM host_cgroup_cpu_usage_seconds_total WHERE cgroup = 'ci.slice'"
  step "5. an err-priority line (logger -p user.err)" mo_root "logger -p user.err -t anvil-monitoring anvil-monitoring-err-$MO_TAG"
  step "5. ... matches the errors dashboard's filter" mo_poll "err line" \
    "SELECT count(*) FROM vector_logs WHERE message = 'anvil-monitoring-err-$MO_TAG' AND \"PRIORITY\" IN ('0', '1', '2', '3')"

  mo_rollback() {
    rollback_only monitoring.toml mo-rollback greptimedb,vector || return 1
    mo_root "rc=0
! docker container inspect greptimedb >/dev/null 2>&1 || { echo 'FAIL: greptimedb container still there'; rc=1; }
for f in /etc/anvil/compose/greptimedb /etc/systemd/system/anvil-compose-greptimedb.service /etc/vector/vector.toml /etc/systemd/system/vector.service /etc/anvil/greptimedb-dashboards; do
  [ ! -e \$f ] && echo \"ok: \$f gone\" || { echo \"FAIL: \$f still there\"; rc=1; }
done
systemctl is-active --quiet vector && { echo 'FAIL: vector still running'; rc=1; } || echo 'ok: vector stopped'
systemctl is-enabled --quiet vector 2>/dev/null && { echo 'FAIL: vector still enabled'; rc=1; } || echo 'ok: vector disabled'
echo \"kept: $MO_DATA (removed next), the vector package\"
exit \$rc"
  }
  step "6. rollback: no GreptimeDB container, Vector stopped and disabled, configs gone" mo_rollback
  # Vector's journal checkpoint too: the real config later starts from scratch.
  step "6. remove the probe container, test data dir, Vector state, images" mo_root \
    "docker rm -f $MO_CTR >/dev/null 2>&1 || true; rm -rf $MO_DATA; find /var/lib/vector -mindepth 1 -delete 2>/dev/null || true
docker image rm $MO_IMG greptime/greptimedb:v1.3.0 >/dev/null 2>&1 || true"
  CLEAN_EXIT=1
  exit 0
fi

# ----------------------------------------- --forgejo-sandbox only ---
# docs/design/acceptance.md "--forgejo-sandbox": as $LOGIN on a Docker host in
# use. Applies only forgejo_runner (mode = "ephemeral", one slot, a unique
# label) against a throwaway repo, runs one workflow in the sandbox, rolls
# forgejo_runner back and deletes the repo. A persistent runner keeps running.
if [[ $SANDBOX == 1 ]]; then
  SB_PORT=${ANVIL_ACCEPT_PORT:-22}
  host "$LOGIN" "$SB_PORT"
  sb_root() { rsudo "$LOGIN" "$SB_PORT" "$1"; }
  # Without ANVIL_ACCEPT_FORGEJO_URL the box runs its own Forgejo behind
  # Caddy on <ip>.sslip.io (public DNS for the IP, a real Let's Encrypt cert).
  SB_SELF=0
  [[ -n ${ANVIL_ACCEPT_FORGEJO_URL:-} ]] || SB_SELF=1
  if [[ $SB_SELF == 1 ]]; then
    [[ $HOST =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "a self-contained Forgejo needs <host> as a public IPv4 (or set ANVIL_ACCEPT_FORGEJO_URL)"
    SB_FQDN=${HOST//./-}.sslip.io SB_ADMIN=accept-admin
    ANVIL_ACCEPT_FORGEJO_URL=https://$SB_FQDN/
  fi
  SB_URL=${ANVIL_ACCEPT_FORGEJO_URL%/}
  SB_TAG=anvil-sandbox-$(date +%s) SB_CTR=anvil-forgejo-runner-1 SB_UNIT=anvil-forgejo-runner-1.service
  # The sandbox lives in root's Docker (sysbox) or in slot user anvil-fjr-1's rootless engine.
  SB_RT=${ANVIL_ACCEPT_SANDBOX_RUNTIME:-sysbox-runc}
  case $SB_RT in
    sysbox-runc) SB_DOCKER=docker SB_SHAPE="{{.State.Running}} {{.HostConfig.Runtime}}" SB_WANT="true sysbox-runc" ;;
    docker-rootless) SB_DOCKER='runuser -u anvil-fjr-1 -- env DOCKER_HOST=unix:///run/user/$(id -u anvil-fjr-1)/docker.sock docker'
      SB_SHAPE="{{.State.Running}} {{.HostConfig.Privileged}}" SB_WANT="true true" ;;
    *) die "ANVIL_ACCEPT_SANDBOX_RUNTIME: sysbox-runc or docker-rootless" ;;
  esac
  if [[ $SB_SELF == 1 ]]; then
    rnd() { openssl rand -hex 24; }
    cat > "$WORK/sb-forge.toml" <<EOF
include = ["host.toml"]
[docker]
[caddy]
[[caddy.site]]
domain = "$SB_FQDN"
upstream = "127.0.0.1:3000"
[forgejo]
domain = "$SB_FQDN"
deploy = "compose"
actions = true
ssh_port = 0
secret_key = "$(rnd)"
internal_token = "$(rnd)"
jwt_secret = "$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=')"
admin_username = "$SB_ADMIN"
admin_email = "admin@accept.invalid"
admin_password = "$(rnd)"
EOF
    chmod 0600 "$WORK/sb-forge.toml"
    sb_forge() {
      ff apply -c "$WORK/sb-forge.toml" --only docker,caddy,forgejo --output json --timeout "$TIMEOUT" > "$WORK/sb-forge.json" || true
      show_modules "$WORK/sb-forge.json"; assert_no_failures "$WORK/sb-forge.json"
    }
    gate "self. apply [docker], [caddy] site $SB_FQDN (Let's Encrypt), [forgejo] compose" sb_forge
    # The admin must change its password at first login, which blocks its
    # API access (tokens too): the CLI lifts that and mints the token
    # (stdout only, never in argv).
    sb_token() {
      local fj="docker exec forgejo /app/gitea/gitea --work-path /var/lib/forgejo --config /etc/forgejo/app.ini"
      if [[ $DRY == 1 ]]; then sb_root "$fj admin user must-change-password --unset $SB_ADMIN; $fj admin user generate-access-token …"; ANVIL_ACCEPT_FORGEJO_API_TOKEN=dry-run; return 0; fi
      ANVIL_ACCEPT_FORGEJO_API_TOKEN=$(sb_root "for _ in \$(seq 60); do curl -fsS -o /dev/null --max-time 5 $SB_URL/api/healthz && break; sleep 5; done
curl -fsS -o /dev/null --max-time 10 $SB_URL/api/healthz || { echo 'no valid https on $SB_URL' >&2; exit 1; }
$fj admin user must-change-password --unset $SB_ADMIN >/dev/null
$fj admin user generate-access-token --username $SB_ADMIN --token-name $SB_TAG --scopes write:repository,write:user --raw" | tail -n1) || return 1
      [[ -n $ANVIL_ACCEPT_FORGEJO_API_TOKEN ]]
    }
    gate "self. $SB_URL answers over valid https; API token minted for $SB_ADMIN" sb_token
    ANVIL_ACCEPT_SANDBOX_EXTRA=${ANVIL_ACCEPT_SANDBOX_EXTRA:-$WORK/sb-extra.toml}
    printf '[docker]\n' > "$WORK/sb-extra.toml"
  fi
  [[ $DRY == 1 || -n ${ANVIL_ACCEPT_FORGEJO_API_TOKEN:-} ]] || die "--forgejo-sandbox needs ANVIL_ACCEPT_FORGEJO_API_TOKEN with ANVIL_ACCEPT_FORGEJO_URL"
  export ANVIL_ACCEPT_FORGEJO_API_TOKEN=${ANVIL_ACCEPT_FORGEJO_API_TOKEN:-dry-run}
  # sb_api <method> <path> [json]: the Forgejo API from here; the token on stdin.
  sb_api() {
    if [[ $DRY == 1 ]]; then printf '  + curl -X %s %s/api/v1%s %s\n' "$1" "$SB_URL" "$2" "${3:-}" >&2; echo '{}'; return 0; fi
    printf 'header = "Authorization: token %s"\n' "$ANVIL_ACCEPT_FORGEJO_API_TOKEN" |
      curl -fsS --proto '=https' --max-time 60 -K - -X "$1" -H 'Content-Type: application/json' \
        ${3:+--data-binary "$3"} "$SB_URL/api/v1$2"
  }
  SB_LOGIN=$(sb_api GET /user | jq -r '.login // "<login>"') || die "GET $SB_URL/api/v1/user failed: check ANVIL_ACCEPT_FORGEJO_URL and the token"
  SB_REPO=$SB_LOGIN/$SB_TAG
  {
    printf 'include = ["host.toml"]\n'
    [[ -z ${ANVIL_ACCEPT_SANDBOX_EXTRA:-} ]] || cat "$ANVIL_ACCEPT_SANDBOX_EXTRA"
    printf '[forgejo_runner]\nmode = "ephemeral"\nurl = "%s/"\napi_token = "${ANVIL_ACCEPT_FORGEJO_API_TOKEN}"\nowner = "%s"\nlabels = ["%s:host"]\nsandbox_runtime = "%s"\n' \
      "$SB_URL" "$SB_REPO" "$SB_TAG" "$SB_RT"
  } > "$WORK/sandbox.toml"
  chmod 0600 "$WORK/sandbox.toml"
  gate "doctor ($LOGIN@$SB_PORT)" ff doctor -c "$WORK/sandbox.toml" --timeout 60
  gate "0. Docker host, no ephemeral forgejo slot yet" sb_root "systemctl is-active --quiet docker || { echo 'not a Docker host'; exit 1; }
! systemctl cat $SB_UNIT >/dev/null 2>&1 || { echo '$SB_UNIT already exists'; exit 1; }"
  # A persistent runner here must stop for the sandboxes and come back on rollback.
  SB_PERSIST=0
  sb_persist() {
    local out
    out=$(sb_root "systemctl is-active --quiet anvil-forgejo-runner.service && echo active || echo inactive") || return 1
    [[ $out == *inactive* ]] || SB_PERSIST=1
    note "persistent runner before: $out"
  }
  step "0. record the persistent runner's state" sb_persist
  sb_daemon_json() {
    ff diff -c "$WORK/sandbox.toml" --only forgejo_runner --output json --timeout "$TIMEOUT" > "$WORK/sb-diff.json" || return 1
    [[ $DRY == 1 ]] && return 0
    local bad
    bad=$(jq -r '[.[0].files[]? | select(.path == "/etc/docker/daemon.json" and (.change == "create" or .change == "modify"))] | length' "$WORK/sb-diff.json")
    [[ $bad == 0 ]] || { note "daemon.json would change: put this host's [docker]/[github_runner] in ANVIL_ACCEPT_SANDBOX_EXTRA"; return 1; }
  }
  gate "0. diff --only forgejo_runner leaves daemon.json (and dockerd) alone" sb_daemon_json
  gate "1. throwaway repo $SB_REPO" sb_api POST /user/repos "{\"name\":\"$SB_TAG\",\"private\":true,\"auto_init\":true}"
  sb_apply() {
    ff apply -c "$WORK/sandbox.toml" --only forgejo_runner --output json --timeout "$TIMEOUT" > "$WORK/sb-apply.json" || true
    show_modules "$WORK/sb-apply.json"; assert_no_failures "$WORK/sb-apply.json"
  }
  step "2. apply forgejo_runner mode = \"ephemeral\" (--only)" sb_apply
  sb_again() {
    local rc=0
    ff apply -c "$WORK/sandbox.toml" --only forgejo_runner --output json --timeout "$TIMEOUT" > "$WORK/sb-reapply.json" || true
    assert_all_ok "$WORK/sb-reapply.json" || return 1
    ff check -c "$WORK/sandbox.toml" --only forgejo_runner --output json --timeout "$TIMEOUT" > "$WORK/sb-check.json" || rc=$?
    show_modules "$WORK/sb-check.json"; want_rc 0 "$rc"
  }
  step "2. idempotent: re-apply ok, check 0" sb_again
  step "2. no persistent runner left: unit inactive, its unit and config.yml moved to .anvil.bak" sb_root "rc=0
systemctl is-active --quiet anvil-forgejo-runner.service && { echo 'FAIL: persistent runner still active'; rc=1; } || echo 'ok: persistent runner stopped'
for f in /etc/systemd/system/anvil-forgejo-runner.service /etc/forgejo-runner/config.yml; do
  [ ! -e \$f ] && echo \"ok: \$f gone\" || { echo \"FAIL: \$f still there\"; rc=1; }
done
[ $SB_RT = docker-rootless ] || docker network inspect -f '{{index .Options \"com.docker.network.bridge.name\"}}' anvil-forgejo-sandbox
[ $SB_RT = docker-rootless ] || ! command -v ufw >/dev/null || ufw status | grep -F anvil-fjsb0 || echo 'no ufw rule for anvil-fjsb0 (Forgejo is not on this host?)'
exit \$rc"
  # One ephemeral runner waits for this repo's jobs, in a sysbox sandbox.
  sb_runners() { # <max>: the repo's runners, all ephemeral, at most <max>
    [[ $DRY == 1 ]] && { sb_api GET "/repos/$SB_REPO/actions/runners"; return 0; }
    local r; r=$(sb_api GET "/repos/$SB_REPO/actions/runners") || return 1
    # Forgejo 15 answers with a bare array (routers/api/v1/shared/runners.go).
    printf '%s' "$r" | jq -c '[.[] | {name, ephemeral, status}]'
    printf '%s' "$r" | jq -e --argjson max "$1" 'length <= $max and all(.[]; .ephemeral)' >/dev/null
  }
  sb_waiting() {
    sb_root "for i in \$(seq 1 60); do $SB_DOCKER inspect -f '$SB_SHAPE' $SB_CTR 2>/dev/null | grep -qx '$SB_WANT' && break; sleep 5; done
$SB_DOCKER inspect -f '{{.State.Running}} {{.HostConfig.Runtime}} {{.HostConfig.Privileged}} {{.HostConfig.CgroupParent}}' $SB_CTR" || return 1
    sb_runners 1
  }
  step "3. slot 1 runs a $SB_RT sandbox; one ephemeral runner registered" sb_waiting
  SB_WF=$(printf '%s\n' "on: push" "jobs:" "  probe:" "    runs-on: $SB_TAG" "    steps:" "      - run: |" \
    "          set -eux" "          hostname; cat /proc/1/cgroup" "          [ \"\$(hostname)\" = $SB_CTR ]" \
    "          sudo touch /$SB_TAG" "          docker run --rm docker.io/library/busybox:1.37 echo inner-docker-ok" | base64 | tr -d '\n')
  step "4. push a workflow" sb_api POST "/repos/$SB_REPO/contents/.forgejo/workflows/sandbox.yml" \
    "{\"message\":\"sandbox probe\",\"content\":\"$SB_WF\"}"
  sb_job() {
    [[ $DRY == 1 ]] && { sb_api GET "/repos/$SB_REPO/actions/tasks"; return 0; }
    local st
    for _ in $(seq 1 120); do
      st=$(sb_api GET "/repos/$SB_REPO/actions/tasks" | jq -r '.workflow_runs[0].status // "none"')
      case $st in success) note "job: success"; return 0 ;; failure|cancelled|skipped) note "job: $st"; return 1 ;; esac
      sleep 5
    done
    note "job: still $st after 10 min"; return 1
  }
  step "5. the job ran in the sandbox (hostname $SB_CTR, inner Docker) and passed" sb_job
  sb_gone() {
    sb_root "rc=0
[ ! -e /$SB_TAG ] && echo 'ok: host untouched' || { echo 'FAIL: /$SB_TAG on the host'; rc=1; }
for i in \$(seq 1 60); do $SB_DOCKER exec $SB_CTR true 2>/dev/null && break; sleep 5; done
$SB_DOCKER exec $SB_CTR test ! -e /$SB_TAG && echo 'ok: the next job has a fresh sandbox' || { echo 'FAIL: the job sandbox survived'; rc=1; }
[ -z \"\$(docker ps -aq --filter ancestor=docker.io/library/busybox:1.37)\" ] && echo 'ok: no job container on host Docker' || { echo 'FAIL: job container on host Docker'; rc=1; }
exit \$rc" || return 1
    sb_runners 1
  }
  step "6. job sandbox gone, host untouched, its runner deleted" sb_gone
  step "7. still converged after a job" sb_again
  sb_rollback() {
    rollback_only sandbox.toml sb-rollback forgejo_runner || return 1
    sb_root "rc=0
! docker container inspect $SB_CTR >/dev/null 2>&1 && echo 'ok: no sandbox' || { echo 'FAIL: sandbox still there'; rc=1; }
if [ $SB_RT = docker-rootless ]; then
  ! id anvil-fjr-1 >/dev/null 2>&1 && echo 'ok: slot user gone' || { echo 'FAIL: anvil-fjr-1 still there'; rc=1; }
  for f in /var/lib/anvil-fjr-1 /etc/systemd/user/anvil-sandbox-docker.service /var/lib/anvil-ci/forgejo-runner-sandbox.tar /var/lib/systemd/linger/anvil-fjr-1; do
    [ ! -e \$f ] && echo \"ok: \$f gone\" || { echo \"FAIL: \$f still there\"; rc=1; }
  done
  ! grep -q '^anvil-fjr-1:' /etc/subuid && echo 'ok: subuid range gone' || { echo 'FAIL: subuid range still there'; rc=1; }
fi
for f in /etc/systemd/system/$SB_UNIT /usr/local/libexec/anvil/forgejo-runner-mint.sh /etc/anvil/forgejo-runner/api-token /var/lib/anvil-ci/forgejo-runner-1.img; do
  [ ! -e \$f ] && echo \"ok: \$f gone\" || { echo \"FAIL: \$f still there\"; rc=1; }
done
[ -z \"\$(docker image ls -q anvil-forgejo-runner)\" ] && echo 'ok: image gone' || { echo 'FAIL: image still there'; rc=1; }
! docker network inspect anvil-forgejo-sandbox >/dev/null 2>&1 && echo 'ok: network gone' || { echo 'FAIL: network still there'; rc=1; }
! command -v ufw >/dev/null || ! ufw status | grep -qF anvil-fjsb0 && echo 'ok: no ufw rule' || { echo 'FAIL: ufw rule still there'; rc=1; }
for d in /etc/anvil/forgejo-runner/image /etc/anvil/forgejo-runner; do
  [ ! -e \$d ] && echo \"ok: \$d gone\" || { echo \"FAIL: \$d still there\"; rc=1; }
done
if [ $SB_PERSIST = 1 ]; then
  systemctl is-active --quiet anvil-forgejo-runner.service && echo 'ok: persistent runner back' || { echo 'FAIL: persistent runner not restored'; rc=1; }
fi
exit \$rc" || return 1
    sb_runners 0
  }
  step "8. rollback: slot, sandbox, image, volume, token, network, ufw rule, dirs and its runner gone; persistent runner back" sb_rollback
  step "9. delete the throwaway repo" sb_api DELETE "/repos/$SB_REPO"
  if [[ $SB_SELF == 1 ]]; then
    step "10. self: rollback forgejo and caddy" rollback_only sb-forge.toml sb-forge-rollback forgejo,caddy
    step "10. self: no forgejo container; Caddyfile back to the packaged one" sb_root "rc=0
! docker container inspect forgejo >/dev/null 2>&1 && echo 'ok: no forgejo container' || { echo 'FAIL: forgejo still running'; rc=1; }
! grep -qF $SB_FQDN /etc/caddy/Caddyfile && echo 'ok: no sslip.io site' || { echo 'FAIL: Caddyfile still serves $SB_FQDN'; rc=1; }
exit \$rc"
  fi
  CLEAN_EXIT=1
  exit 0
fi

# ------------------------------------------------------------------ run -----
# The rollback list: every module of the plan except users (22c refuses it).
modules_but_users() {
  [[ $DRY == 1 ]] && { echo "<every module in $1 except users>"; return; }
  jq -r '[.[0].modules[].module | select(. != "users")] | join(",")' "$1"
}

prep() {
  lifeline_open "$LOGIN" 22
  rssh "$LOGIN" 22 'command -v cloud-init >/dev/null && cloud-init status --wait >/dev/null 2>&1; . /etc/os-release && echo "$PRETTY_NAME"; systemctl is-enabled ssh.socket 2>/dev/null || echo "ssh.socket: not enabled"'
}
gate "connect, open lifeline session, wait for cloud-init" prep

validate_all() { local f; for f in step1 cis port containers beszel podman podman-services podman-v2; do ff validate -c "$WORK/$f.toml" >/dev/null || return 1; done; }
step "validate fixtures (local)" validate_all
gate "doctor ($LOGIN@22)" ff doctor -c "$WORK/step1.toml" --timeout 60

# 1. Tutorial step 1, then idempotency.
gate "step-1 apply as $LOGIN (creates $OPS, sshd, firewall, updates)" apply_ok step1.toml step1
host "$OPS" 22
gate "doctor ($OPS@22: user created, key login, sudo -n)" ff doctor -c "$WORK/step1.toml" --timeout 60
step "step-1 idempotent: re-apply ok, check 0, diff empty" converged step1.toml step1

# 2. CIS Level 1, idempotency, score, report.
step "CIS apply" apply_ok cis.toml cis
step "CIS idempotent: re-apply ok, check 0, diff empty" converged cis.toml cis
score() {
  ff score -c "$WORK/cis.toml" --output json --timeout "$TIMEOUT" > "$WORK/score.json"
  [[ $DRY == 1 ]] || jq -r '.[0] | "  lynis hardening index: \(.index // "n/a")"' "$WORK/score.json"
}
step "score (Lynis index)" score
step "status" ff status -c "$WORK/cis.toml" --timeout "$TIMEOUT"
step "report --check" ff report -c "$WORK/cis.toml" --check --timeout "$TIMEOUT"

# 3. Reboot: the hardened state must boot (22b) and stay converged.
reboot_host() {
  local before after=""
  before=$(rssh "$OPS" 22 cat /proc/sys/kernel/random/boot_id)
  lifeline_close
  rssh "$OPS" 22 sudo -n systemctl reboot || true
  if [[ $DRY == 1 ]]; then note "(poll every 10s, up to 10 min: ssh $OPS@$HOST:22 cat boot_id until it changes)"
  else
    sleep 20
    for _ in $(seq 1 30); do   # <= 10 min: 10 s connect timeout + 10 s sleep
      after=$(rssh "$OPS" 22 cat /proc/sys/kernel/random/boot_id 2>/dev/null) && [[ $after != "$before" ]] && break
      sleep 10
    done
    [[ -n $after && $after != "$before" ]] || { note "not back after 10 min: use the provider console"; return 1; }
  fi
  lifeline_open "$OPS" 22
}
gate "reboot, $OPS@22 reachable again" reboot_host
after_boot() {
  local rc=0
  ff check -c "$WORK/cis.toml" --output json --timeout "$TIMEOUT" > "$WORK/boot-check.json" || rc=$?
  show_modules "$WORK/boot-check.json"; want_rc 0 "$rc" || return 1
  local failed; failed=$(rssh "$OPS" 22 systemctl list-units --state=failed --no-legend --plain)
  [[ -z $failed ]] || { note "failed units: $failed"; return 1; }
}
step "after reboot: check 0, no failed units" after_boot

# 4. PAM functional test with pamtester on a throwaway user.
PAM_SCRIPT=$(cat <<'EOF'
export DEBIAN_FRONTEND=noninteractive
u=anvil-accept-pam had=0
dpkg -s pamtester >/dev/null 2>&1 && had=1
cleanup() {
  faillock --user "$u" --reset >/dev/null 2>&1 || true
  userdel -r "$u" >/dev/null 2>&1 || true
  [ "$had" = 1 ] || apt-get purge -y -qq pamtester </dev/null >/dev/null 2>&1 || true
}
trap cleanup EXIT
apt-get install -y -qq -o DPkg::Lock::Timeout=300 pamtester </dev/null >/dev/null \
  || { apt-get update -qq </dev/null && apt-get install -y -qq -o DPkg::Lock::Timeout=300 pamtester </dev/null >/dev/null; }
pw="Aa1-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
useradd -m -s /usr/sbin/nologin "$u"
printf '%s:%s\n' "$u" "$pw" | chpasswd
auth() { printf '%s\n' "$1" | pamtester login "$u" authenticate >/dev/null 2>&1; }
auth "$pw" || { echo "correct password rejected"; exit 1; }
for i in 1 2 3 4 5; do ! auth "wrong-$i" || { echo "wrong password accepted"; exit 1; }; done
! auth "$pw" || { echo "not locked after 5 failures"; exit 1; }
faillock --user "$u" --reset
auth "$pw" || { echo "still locked after faillock --reset"; exit 1; }
echo "  pam: correct ok, 5 wrong -> locked, reset -> ok"
EOF
)
step "PAM: pamtester correct ok, 5 wrong locks, reset unlocks" rsudo "$OPS" 22 "$PAM_SCRIPT"

# 5. Drift: hand-edit a managed file (a comment: no runtime effect).
drift() {
  local rc=0
  rsudo "$OPS" 22 "printf '# anvil acceptance: hand edit\n' >> /etc/sysctl.d/99-anvil-kernel.conf"
  ff check -c "$WORK/cis.toml" --output json --timeout "$TIMEOUT" > "$WORK/drift-check.json" || rc=$?
  want_rc 1 "$rc" && assert_status "$WORK/drift-check.json" kernel drifted || return 1
  ff diff -c "$WORK/cis.toml" --output json --timeout "$TIMEOUT" > "$WORK/drift-diff.json"
  if [[ $DRY == 0 ]]; then
    jq -e '.[0].files[] | select(.path == "/etc/sysctl.d/99-anvil-kernel.conf" and .change == "modify")' \
      "$WORK/drift-diff.json" >/dev/null || { note "diff does not show the edit"; return 1; }
  fi
  apply_ok cis.toml drift-apply && assert_status "$WORK/drift-apply.json" kernel changed || return 1
  rc=0; ff check -c "$WORK/cis.toml" --output json --timeout "$TIMEOUT" > "$WORK/drift-check2.json" || rc=$?
  want_rc 0 "$rc"
}
step "drift: hand edit -> check 1, diff shows it, apply fixes, check 0" drift

# 6. Opt-in module stages: apply, converged, own checks, rollback --only.
if [[ $CONTAINERS == 1 ]]; then
  step "containers: apply" apply_ok containers.toml containers
  step "containers: idempotent" converged containers.toml containers
  step "containers: 127.0.0.1:18080 answers on the host" rssh "$OPS" 22 curl -fsS -o /dev/null http://127.0.0.1:18080
  public_filtered() { # with iptables=false, ufw must filter a 0.0.0.0 publish
    run curl -fsS -o /dev/null --max-time 5 "http://$HOST:18081" || return 0
    [[ $DRY == 1 ]] && return 0
    note "0.0.0.0:18081 is reachable from here: ufw did not filter it"; return 1
  }
  step "containers: 0.0.0.0:18081 refused from this machine (ufw)" public_filtered
  outbound() { # informational, Docker documents outbound as lost
    rssh "$OPS" 22 'sudo -n docker run --rm alpine wget -q -T 5 -O /dev/null http://deb.debian.org && echo "  container outbound: works" || echo "  container outbound: none"'
  }
  step "containers: container outbound (informational)" outbound
  step "containers: rollback --only containers,docker" rollback_only containers.toml containers-rollback containers,docker
fi
if [[ $BESZEL == 1 ]]; then
  step "beszel: apply" apply_ok beszel.toml beszel
  step "beszel: idempotent" converged beszel.toml beszel
  step "beszel: hub and agent active" rssh "$OPS" 22 systemctl is-active beszel-hub beszel-agent
  step "beszel: sandbox exposure (informational)" rssh "$OPS" 22 'sudo -n systemd-analyze security beszel-agent beszel-hub --no-pager | tail -n 2; sudo -n journalctl -u beszel-agent -u beszel-hub -p err -b --no-pager | tail -n 20'
  step "beszel: rollback --only beszel" rollback_only beszel.toml beszel-rollback beszel
  step "beszel: units gone, /var/lib/beszel-hub kept" rssh "$OPS" 22 '! systemctl cat beszel-agent >/dev/null 2>&1 && ! systemctl cat beszel-hub >/dev/null 2>&1 && sudo -n test -d /var/lib/beszel-hub'
fi

if [[ $PODMAN == 1 ]]; then
  public_refused() { # rootful netavark DNATs past ufw: a public PublishPort never validates
    local rc=0; ff validate -c "$WORK/podman-public.toml" || rc=$?
    [[ $DRY == 1 ]] || [[ $rc != 0 ]] || { note "podman-public.toml validated"; return 1; }
  }
  step "podman: public PublishPort refused by validate (local)" public_refused
  both_refused() { # one engine per host
    local rc=0; ff validate -c "$WORK/podman-docker.toml" || rc=$?
    [[ $DRY == 1 ]] || [[ $rc != 0 ]] || { note "podman-docker.toml validated"; return 1; }
  }
  step "podman: [docker] + [podman] refused by validate (local)" both_refused
  step "podman: apply (Podman >= 4.4 gate, quadlet)" apply_ok podman.toml podman
  step "podman: idempotent" converged podman.toml podman
  step "podman: 127.0.0.1:18090 answers on the host" rssh "$OPS" 22 curl -fsS -o /dev/null http://127.0.0.1:18090
  step "podman: [podman] drop-in caps logs, keeps the iptables driver" rssh "$OPS" 22 \
    'grep -qx "log_size_max = 10485760" /etc/containers/containers.conf.d/99-anvil.conf && grep -qx "firewall_driver = \"iptables\"" /etc/containers/containers.conf.d/99-anvil.conf'
  step "podman: the quadlet container logs to k8s-file" rssh "$OPS" 22 \
    'test "$(sudo -n podman inspect --format "{{.HostConfig.LogConfig.Type}}" systemd-anvil-accept)" = k8s-file'
  step "podman: rollback --only containers,podman" rollback_only podman.toml podman-rollback containers,podman
  step "podman: quadlet, unit and drop-in gone, podman package and image kept" rssh "$OPS" 22 \
    '! test -e /etc/containers/systemd/anvil-accept.container && ! test -e /etc/containers/containers.conf.d/99-anvil.conf && ! systemctl is-active --quiet anvil-accept.service && command -v podman >/dev/null && sudo -n podman image exists docker.io/library/nginx:alpine'
  # Forgejo, GreptimeDB and Headplane as Quadlets, no Docker anywhere.
  # While apply bootstraps the admin, no process argv may hold its
  # password. Sampled every 50 ms: strong evidence, not proof. The password is
  # in the script (stdin), and grep reads it from a file, so neither leaks it.
  ARGV_SAMPLER='p=$(mktemp); trap "rm -f $p /run/anvil-argv-stop" EXIT
printf "%s\n" accept-password-not-secret > "$p"; rm -f /run/anvil-argv-stop
n=0 hit=0
while [ ! -e /run/anvil-argv-stop ] && [ $n -lt 40000 ]; do
  for f in $(grep -lsaF -f "$p" /proc/[0-9]*/cmdline || true); do
    d=${f%/cmdline}; echo "LEAK: pid ${d#/proc/} $(cat "$d/comm" 2>/dev/null)"; hit=1
  done
  n=$((n + 1)); sleep 0.05
done
echo "$n argv samples"; [ $hit = 0 ] && [ $n -gt 20 ]'
  argv_sampler_start() {
    if [[ $DRY == 1 ]]; then rsudo "$OPS" 22 "$ARGV_SAMPLER"; return; fi
    rsudo "$OPS" 22 "$ARGV_SAMPLER" > "$WORK/argv-sampler.log" 2>&1 & ARGV_SAMPLER_PID=$!
    sleep 2
  }
  argv_sampler_check() {
    rsudo "$OPS" 22 'touch /run/anvil-argv-stop'
    [[ $DRY == 1 ]] && return 0
    local rc=0; wait "$ARGV_SAMPLER_PID" || rc=$?
    cat "$WORK/argv-sampler.log"; return $rc
  }
  argv_sampler_start
  step "podman: apply forgejo/greptimedb/headplane quadlets" apply_ok podman-services.toml podman-services
  step "podman: no process argv held the forgejo admin password during apply" argv_sampler_check
  step "podman: services idempotent" converged podman-services.toml podman-services
  # Unit active is not enough (Debian, round 6: headplane.service active, no
  # container): each container must be running and its port answer, within
  # 90s; on failure the unit's status, journal and `podman ps -a`.
  services_up() {
    rsudo "$OPS" 22 "containers=$CONTAINERS"'
up() { # <unit> <container> <url> [curl -f]
  for _ in $(seq 90); do
    [ "$(podman container inspect -f "{{.State.Running}}" "$2" 2>/dev/null)" = true ] \
      && curl -sS ${4:-} -o /dev/null --max-time 5 "$3" 2>/dev/null && return 0
    sleep 1
  done
  echo "== $1: $2 not serving $3"; systemctl status "$1" --no-pager 2>&1 | tail -n 5
  journalctl -u "$1" -n 30 --no-pager; podman ps -a --filter "name=$2"; return 1
}
rc=0
systemctl is-active --quiet headscale && runuser -u headscale -- test -r /var/lib/headscale/noise_private.key \
  || { echo "== headscale"; ls -ld /var/lib/headscale; journalctl -u headscale -n 20 --no-pager; rc=1; }
up forgejo.service forgejo http://127.0.0.1:3000/api/healthz -f || rc=1
up anvil-greptimedb.service greptimedb http://127.0.0.1:4000/health -f || rc=1
up headplane.service headplane http://127.0.0.1:3001/admin || rc=1
# No Docker engine (a podman-docker shim at /usr/bin/docker is fine). After
# --containers, its docker-ce stays by design (rollback keeps packages).
[ "$containers" = 1 ] || for pkg in docker-ce docker.io; do ! dpkg -s "$pkg" >/dev/null 2>&1 || { echo "$pkg is installed"; rc=1; }; done
exit $rc'
  }
  step "podman: headscale up; forgejo, greptimedb, headplane containers running and answering on loopback; no Docker engine" services_up
  step "podman: forgejo admin bootstrapped with the configured password, jail log written" rssh "$OPS" 22 \
    'sudo -n podman exec forgejo /app/gitea/gitea --work-path /var/lib/forgejo --config /etc/forgejo/app.ini admin user list | grep -w accept-admin >/dev/null && test "$(curl -s -o /dev/null -w %{http_code} -u accept-admin:accept-password-not-secret http://127.0.0.1:3000/api/v1/user)" = 403 && test "$(curl -s -o /dev/null -w %{http_code} -u accept-admin:wrong http://127.0.0.1:3000/api/v1/user)" = 401 && sudo -n test -s /var/lib/forgejo/log/forgejo.log'
  # What the user gets: Forgejo comes back after restarts, on the same data.
  FJ_RESTART='for i in 1 2; do sudo -n systemctl restart forgejo.service || exit 1; ok=; for _ in $(seq 60); do curl -fsS -o /dev/null http://127.0.0.1:3000/api/healthz && { ok=1; break; }; sleep 1; done; [ -n "$ok" ] || exit 1; done; sudo -n podman exec forgejo /app/gitea/gitea --work-path /var/lib/forgejo --config /etc/forgejo/app.ini admin user list | grep -w accept-admin >/dev/null'
  step "podman: forgejo survives systemctl restart twice, admin kept" rssh "$OPS" 22 "$FJ_RESTART"
  step "podman: rollback --only forgejo,greptimedb,podman" rollback_only podman-services.toml podman-services-rollback forgejo,greptimedb,podman
  step "podman: quadlets gone, services stopped, forgejo DB and data dirs kept" rssh "$OPS" 22 \
    'for q in forgejo anvil-greptimedb; do ! test -e /etc/containers/systemd/$q.container || exit 1; ! systemctl is-active --quiet $q.service || exit 1; done; sudo -n test -s /var/lib/forgejo/data/forgejo.db && sudo -n test -d /var/lib/greptimedb'
  V2_UNIT=anvil-github-runner-accept-1.service V2_AA=anvil-github-runner-sandbox
  step "podman: v2 runner apply (Podman sandbox, image build, AppArmor)" apply_ok podman-v2.toml podman-v2
  step "podman: v2 runner idempotent" converged podman-v2.toml podman-v2
  step "podman: v2 slot active, image built, id range, profile loaded where AppArmor is on" rssh "$OPS" 22 \
    "systemctl is-active --quiet $V2_UNIT && sudo -n podman image ls localhost/anvil-github-runner --format '{{.Tag}}' | grep -q . && grep -q '^containers:' /etc/subuid /etc/subgid && { ! sudo -n aa-enabled -q 2>/dev/null || sudo -n grep -q '^$V2_AA ' /sys/kernel/security/apparmor/profiles; }"
  # A sandbox started like a slot's (the unit's own NoNewPrivileges, the
  # minter's options): rootless Podman as runner must map ids and run, also
  # on a netavark bridge network as job services: get.
  V2_SELFTEST='img=$(sudo -n podman image ls localhost/anvil-github-runner --format "{{.Repository}}:{{.Tag}}" | head -n1)
nnp=$(systemctl show -P NoNewPrivileges anvil-github-runner-accept-1.service)
aa=; ! sudo -n aa-enabled -q 2>/dev/null || aa=--security-opt=apparmor=anvil-github-runner-sandbox
sudo -n systemd-run --quiet --wait --pipe --collect -p NoNewPrivileges="$nnp" \
  podman run --rm --userns=auto:size=65536 --device /dev/fuse --device /dev/net/tun \
  --security-opt unmask=ALL --security-opt label=disable $aa \
  --mount type=tmpfs,destination=/home/runner/.local/share/containers,tmpfs-mode=1777 \
  --entrypoint bash "$img" -c "install -d -m 0700 -o runner -g runner /run/user/1001 && \
  runuser -u runner -- env XDG_RUNTIME_DIR=/run/user/1001 sh -ec \"podman run --rm docker.io/library/alpine:3 true; \
  podman network create anvil-selftest >/dev/null; podman run --rm --network anvil-selftest docker.io/library/alpine:3 true\""'
  step "podman: v2 sandbox runs a rootless container as runner (unit's NoNewPrivileges)" rssh "$OPS" 22 "$V2_SELFTEST"
  step "podman: v2 rollback --only github_runner" rollback_only podman-v2.toml podman-v2-rollback github_runner
  step "podman: v2 slot, image and profile gone, podman kept" rssh "$OPS" 22 \
    "! systemctl cat $V2_UNIT >/dev/null 2>&1 && ! sudo -n podman image ls localhost/anvil-github-runner --format '{{.Tag}}' | grep -q . && ! test -e /etc/apparmor.d/$V2_AA && command -v podman >/dev/null"
  runner_on_docker_refused() { # docker = "podman" needs a Podman host
    local rc=0; ff validate -c "$WORK/podman-runner-docker.toml" || rc=$?
    [[ $DRY == 1 ]] || [[ $rc != 0 ]] || { note "podman-runner-docker.toml validated"; return 1; }
  }
  step "podman runner: docker = \"podman\" on a Docker host refused by validate (local)" runner_on_docker_refused
  # Without ANVIL_ACCEPT_FORGEJO_TOKEN the fixture's fake token makes the
  # daemon exit and restart; only the steps that need a live runner skip.
  step "podman runner: apply forgejo_runner docker = \"podman\"" apply_ok podman-runner.toml podman-runner
  step "podman runner: subuid/subgid range, newuidmap setuid or caps, linger + user bus" rssh "$OPS" 22 \
    'grep -q "^forgejo-runner:" /etc/subuid && grep -q "^forgejo-runner:" /etc/subgid && { test -u /usr/bin/newuidmap || getcap /usr/bin/newuidmap | grep -q cap_setuid; } && test -e /var/lib/systemd/linger/forgejo-runner && sudo -n test -S "/run/user/$(id -u forgejo-runner)/bus"'
  # Round 6: without Delegate=yes the unit's podman service moved into
  # user@<uid>.service, one more per restart, and its containers left
  # ci.slice and the caps. runner_cgroups <want>: "1" = exactly one podman
  # service; "le1" = at most one (the fake token's restart loop may be between
  # starts). Every runner-user podman/conmon/container process must be in the
  # unit's cgroup.
  runner_cgroups() {
    rsudo "$OPS" 22 "want=$1"'
cg=/ci.slice/anvil-forgejo-runner.service
uid=$(id -u forgejo-runner)
# On any failure (also an unexpected exit): every runner-uid process, its cgroup, and the unit tree.
trap '"'"'[ $? = 0 ] || { echo "== forgejo-runner processes (pid comm cgroup args)"
  for p in $(pgrep -u forgejo-runner || true); do
    printf "%s %s %s %s\n" "$p" "$(cat /proc/$p/comm 2>/dev/null)" "$(cat /proc/$p/cgroup 2>/dev/null)" "$(tr "\0" " " < /proc/$p/cmdline 2>/dev/null)"
  done; systemd-cgls --no-pager -u anvil-forgejo-runner.service 2>&1 | head -n 40 || true; }'"'"' EXIT
svc=0 rc=0
for d in /proc/[0-9]*; do
  c=$(cat "$d/cgroup" 2>/dev/null) || continue
  comm=$(cat "$d/comm" 2>/dev/null) || continue
  owner=$(stat -c %u "$d" 2>/dev/null) || continue
  # The pause process keeps podman'"'"'s argv: count only comm "podman".
  if [ "$owner" = "$uid" ] && [ "$comm" = podman ]; then
    case $(tr "\0" " " < "$d/cmdline" 2>/dev/null || true) in *" system service "*) svc=$((svc + 1)) ;; esac
  fi
  case $c in
    *"/user@$uid.service/"*)
      # The user manager, its bus, the pause process and aardvark-dns live here by design.
      case $comm in systemd|"(sd-pam)"|dbus-daemon|dbus-broker*|"podman pause"|aardvark-dns) echo "user manager: $comm" ;;
        *) echo "ESCAPED: ${d#/proc/} $comm: $c"; rc=1 ;; esac ;;
    *"$cg"*) ;;
    *) # Anything else of the runner that is podman, conmon or a container.
      [ "$owner" = "$uid" ] || continue
      case "$comm $c" in podman\ *|conmon\ *|*libpod*) echo "OUTSIDE: ${d#/proc/} $comm: $c"; rc=1 ;; esac ;;
  esac
done
echo "podman services: $svc (want $want)"
if [ "$want" = 1 ]; then [ "$svc" = 1 ] || rc=1; else [ "$svc" -le 1 ] || rc=1; fi
exit $rc'
  }
  leak_free() { [[ $DRY == 1 ]] || sleep 30; runner_cgroups le1; }
  step "podman runner: 30s of the unit's restarts leak no podman service, all runner processes in the unit" leak_free
  if [[ $DRY == 1 || -n ${ANVIL_ACCEPT_FORGEJO_TOKEN:-} ]]; then
    step "podman runner: idempotent" converged podman-runner.toml podman-runner
    step "podman runner: unit active, its podman socket" rssh "$OPS" 22 \
      'systemctl is-active --quiet anvil-forgejo-runner.service && sudo -n test -S "/run/user/$(id -u forgejo-runner)/forgejo-runner/podman.sock"'
    # The evidence for the PR: a container started through the runner's socket
    # is in the runner unit's cgroup (ci.slice, its MemoryMax) and its
    # root is the forgejo-runner uid, not host root.
    in_slice() {
      rsudo "$OPS" 22 '
xdg=/run/user/$(id -u forgejo-runner)
p() { runuser -u forgejo-runner -- env XDG_RUNTIME_DIR="$xdg" CONTAINER_HOST="unix://$xdg/forgejo-runner/podman.sock" podman "$@"; }
cid=$(p run -d --rm docker.io/library/alpine:3 sleep 120)
pid=$(p inspect -f "{{.State.Pid}}" "$cid")
cat "/proc/$pid/cgroup"; systemctl show -p MemoryMax anvil-forgejo-runner.service
# Not asserted, for the PR: helpers the user manager may hold (outside the slice).
for h in "pause:$(cat "$xdg/libpod/tmp/pause.pid" 2>/dev/null)" "aardvark-dns:$(pgrep -u forgejo-runner -x aardvark-dns | head -n1)"; do
  [ -z "${h#*:}" ] || printf '%s %s\n' "${h%%:*}" "$(cat "/proc/${h#*:}/cgroup" 2>/dev/null)"
done
rc=0
grep -q "/ci.slice/anvil-forgejo-runner.service" "/proc/$pid/cgroup" || rc=1
[ "$(stat -c %u "/proc/$pid")" = "$(id -u forgejo-runner)" ] || rc=1
p rm -f "$cid" >/dev/null
exit $rc'
    }
    step "podman runner: job container in ci.slice/anvil-forgejo-runner.service, root = forgejo-runner" in_slice
    # Round 4: a restart killed the pause process but left its pid file
    # in the lingering /run/user/<uid>; the next start could not join it.
    restart_twice() {
      rsudo "$OPS" 22 '
u=anvil-forgejo-runner.service
xdg=/run/user/$(id -u forgejo-runner)
for _ in 1 2; do
  systemctl restart "$u"
  for _ in $(seq 100); do [ -S "$xdg/forgejo-runner/podman.sock" ] && break; sleep 0.1; done
done
systemctl is-active --quiet "$u" || { systemctl status "$u" --no-pager | tail -n 20; exit 1; }
runuser -u forgejo-runner -- env XDG_RUNTIME_DIR="$xdg" CONTAINER_HOST="unix://$xdg/forgejo-runner/podman.sock" \
  podman run --rm docker.io/library/alpine:3 true'
    }
    step "podman runner: restarted twice, still active and runs a rootless container" restart_twice
    restart_thrice() {
      rsudo "$OPS" 22 '
u=anvil-forgejo-runner.service
xdg=/run/user/$(id -u forgejo-runner)
for _ in 1 2 3; do
  systemctl restart "$u"
  for _ in $(seq 100); do [ -S "$xdg/forgejo-runner/podman.sock" ] && break; sleep 0.1; done
done
systemctl is-active --quiet "$u"' && runner_cgroups 1 && in_slice
    }
    step "podman runner: restart x3, one podman service, every runner process and a socket container in the unit's cgroup" restart_thrice
  else
    RESULTS+=("SKIP  podman runner: idempotency + in-slice evidence need ANVIL_ACCEPT_FORGEJO_URL/_UUID/_TOKEN (a real runner)")
  fi
  # The unit's own [Service] lines (drop-ins included: slice, caps, hardening,
  # no NoNewPrivileges) as systemd-run -p, the unit stopped: rootless Podman as
  # forgejo-runner must map ids, run alpine, and reach out from a bridge
  # network as job services do. On failure, show the AppArmor denials.
  runner_selftest() {
    local s
    s=$(cat <<'EOS'
u=anvil-forgejo-runner.service
systemctl stop "$u"
props=()
while IFS= read -r l; do props+=(-p "$l"); done < <(systemctl cat "$u" | sed -n '/^\[Service\]/,/^\[/p' \
  | grep -E '^[A-Za-z]+=' | grep -vE '^(ExecStart|ExecReload|Restart|RestartSec|KillMode|TimeoutStopSec)=')
printf '%s\n' "${props[@]}" | grep -v '^-p$'
# sd-bus finds the user bus only at $XDG_RUNTIME_DIR/bus (aardvark-dns).
xdg=/run/user/$(id -u forgejo-runner)
printf '%s\n' "${props[@]}" | grep -qx "Environment=XDG_RUNTIME_DIR=$xdg" \
  || { echo "unit XDG_RUNTIME_DIR is not $xdg"; systemctl start "$u"; exit 1; }
# The service's own runroot/tmpdir: podman refuses a db opened with others.
flags=$(systemctl cat "$u" | grep -o -- '--runroot [^ ]* --tmpdir [^ ]*' | head -n1)
rc=0
systemd-run --quiet --wait --pipe --collect "${props[@]}" /bin/sh -ec '
[ "$XDG_RUNTIME_DIR" = "/run/user/$(id -u)" ] || { echo "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"; exit 1; }
flags="$*"
p() { env -u CONTAINER_HOST podman --cgroup-manager=cgroupfs $flags "$@"; }
p run --rm docker.io/library/alpine:3 true
p network create anvil-selftest >/dev/null
trap "p network rm -f anvil-selftest >/dev/null" EXIT
p run --rm --network anvil-selftest docker.io/library/alpine:3 wget -q --spider http://deb.debian.org/
# What actions/runner does to every job container (round 5): the rootless
# socket of the unit must answer at /var/run/docker.sock, via the podman-docker
# shim as a client of the service of the unit.
sock=${DOCKER_HOST#unix://}
p system service --time=0 "unix://$sock" & svc=$!
for _ in $(seq 100); do [ -S "$sock" ] && break; sleep 0.1; done
echo "/var/run/docker.sock -> $(readlink -f /var/run/docker.sock)"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker.io/library/alpine:3 test -S /var/run/docker.sock
kill "$svc"' sh $flags || rc=$?
[ "$rc" = 0 ] || { grep -h 'apparmor="DENIED"' /var/log/audit/audit.log 2>/dev/null | tail -n 10 || true; journalctl -k -g 'apparmor="DENIED"' -n 10 --no-pager 2>/dev/null || true; }
systemctl start "$u"
exit "$rc"
EOS
)
    rsudo "$OPS" 22 "$s"
  }
  step "podman runner: rootless containers under the unit's own settings (systemd-run -p, bridge + outbound, docker.sock mount)" runner_selftest
  step "podman runner: rollback --only forgejo_runner,ci_resources,podman" rollback_only podman-runner.toml podman-runner-rollback forgejo_runner,ci_resources,podman
  step "podman runner: unit, subuids, linger and user gone, home (container storage) kept" rssh "$OPS" 22 \
    '! test -e /etc/systemd/system/anvil-forgejo-runner.service && ! grep -q "^forgejo-runner:" /etc/subuid && ! test -e /var/lib/systemd/linger/forgejo-runner && ! id forgejo-runner >/dev/null 2>&1 && sudo -n test -d /var/lib/forgejo-runner'
fi

# 7. Port move 22 -> 2222, then the rollback cycle.
# reach <port>: a fresh login as ops on <port>, and sshd listening there.
reach() { rssh "$OPS" "$1" true && rssh "$OPS" "$1" "ss -Htln 'sport = :$1' | grep . >/dev/null"; }
step "pre-open $NEW_PORT in ufw (guard: a dropped session mid-move cannot lock out)" \
  rssh "$OPS" 22 sudo -n ufw allow "$NEW_PORT/tcp"
port_move() {
  apply_ok port.toml port-move || return 1
  assert_status "$WORK/port-move.json" sshd changed
}
gate "port move: apply sshd.port=$NEW_PORT as $OPS@22" port_move
gate "port move: fresh login $OPS@$NEW_PORT, sshd listens on $NEW_PORT" reach "$NEW_PORT"
host "$OPS" "$NEW_PORT"
step "port move: idempotent on $NEW_PORT" converged port.toml port
# Close the old port by hand (anvil never deletes ufw rules) so the rollback
# below must re-open 22 itself. Safe: login on 2222 is proven above.
gate "close old port: ufw delete allow 22/tcp" \
  rssh "$OPS" "$NEW_PORT" "sudo -n ufw delete allow 22/tcp && ! sudo -n ufw status | grep -E '^22(/tcp)?[[:space:]]' >/dev/null"
rollback_cycle() {
  local only; only=$(modules_but_users "$WORK/port-move.json")
  rollback_only port.toml rollback "$only"
}
step "rollback everything but users (as $OPS@$NEW_PORT)" rollback_cycle
gate "after rollback: fresh login $OPS@22, sshd listens on 22" reach 22
host "$OPS" 22
after_rollback() {
  local rc=0
  ff check -c "$WORK/cis.toml" --output json --timeout "$TIMEOUT" > "$WORK/rollback-check.json" || rc=$?
  show_modules "$WORK/rollback-check.json"; want_rc 1 "$rc"
}
step "after rollback: check reports drift (exit 1)" after_rollback
step "re-apply CIS on 22" apply_ok cis.toml final
step "final: re-apply ok, check 0, diff empty" converged cis.toml final
step "remove the hand-added ufw rule for $NEW_PORT" rssh "$OPS" 22 sudo -n ufw delete allow "$NEW_PORT/tcp"
CLEAN_EXIT=1
