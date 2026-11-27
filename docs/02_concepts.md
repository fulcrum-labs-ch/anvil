# What anvil changes, and how it undoes it

anvil never resets a server to generic "defaults". Before it changes
anything on a host, it records what was there. `rollback` puts exactly that
back. A server that came preconfigured (by your provider, an image, or you) is
the normal case, and its settings survive.

## Terms

- **Module**: one hardening area, such as `sshd` or `firewall`. Enabled by
  its `[section]` in the config.
- **Desired state**: what your config says the host should look like.
- **Probe**: a read-only check that compares the host with the desired state.
  It writes nothing.
- **Converge**: make the change that fixes a mismatch.
- **Drift**: a managed setting that no longer matches the config, usually
  because someone edited it by hand. `check` reports it.
- **Idempotent**: running the same step again changes nothing once the host
  already matches. `apply` is safe to re-run.
- **Drop-in**: a small extra file in a config directory, such as
  `/etc/ssh/sshd_config.d/05-anvil.conf`. The main config loads it, so anvil
  never has to edit your main file.
- **Rollback**: undo anvil's file changes. See below.

## How each kind of change is made and recorded

| anvil… | Example | Recorded before the first change | `rollback` |
|---|---|---|---|
| **adds its own drop-in file**: most modules | `/etc/ssh/sshd_config.d/05-anvil.conf`, `/etc/sysctl.d/99-anvil-kernel.conf` | nothing needed: your files are not touched | deletes its drop-in; your settings apply again |
| **replaces a file that already existed** | `/etc/security/pwquality.conf` | a byte-exact copy, `<file>.anvil.bak` (content, mode, owner) | copies it back |
| **creates a file that didn't exist** | `/etc/sudoers.d/admin` | the path, in `/var/lib/anvil/created` | deletes it |
| **edits a shared file in place** | `UMASK` / `PASS_*` in `/etc/login.defs` | only the lines it is about to change | puts those lines back, leaves the rest |
| **changes live kernel settings** | `kernel.sysrq`, `net.ipv4.conf.*` | the live values, `/var/lib/anvil/sysctl-<module>.orig` | re-applies them immediately |
| **strips setuid bits** | `suid` | each binary's original mode, `/var/lib/anvil/suid.state` | restores the modes |
| **runs a command** | install a package, create a user, add a ufw rule | not reversible | left in place (see below) |

Drop-ins are why preconfigured servers are safe. anvil's sshd settings live in
their own file, so if your `sshd_config` already said `PermitRootLogin no`, it
still says so after a rollback. Drop-in names are chosen to win: `05-` in
`sshd_config.d` (first match wins) and `99-` in `sysctl.d`, `apt.conf.d` and
similar (last match wins).

The backup is taken at the **first** change only, so it always holds the
pre-anvil original, never an earlier anvil version.

## What rollback does

- Restores or deletes every file above, module by module (`--only` to pick).
- Reloads the services affected (sshd, auditd, fail2ban, …), so the running
  system matches the files. Rolling back `sshd` therefore re-allows root and
  password login **immediately**, if the original config allowed them.
- Puts back sysctl values and remounts `/tmp` with exec.
- Keeps SSH reachable: the firewall stays on, but whatever port the restored
  sshd listens on is allowed first.
- Refuses to roll back `users` while anvil logs in as an account it created.
  That would delete your own key and sudo rule.

## What rollback does not do

- **Undo commands.** Packages and data are never removed: installed
  packages stay installed, and data (backup repositories, databases) is
  never touched. Created users,
  enabled services and ufw rules stay. (`libpam-pwquality` stays too, so
  password quality falls back to its package defaults.)
- **Keep later hand edits** to a file anvil manages: rollback restores the
  pre-anvil original, not your edit made after anvil.
- **Act as a server backup.** It covers only what anvil changed. Take a
  provider snapshot for anything else.
- **Pick a version.** There is no history of runs to choose from; it always
  returns to before anvil.

Hosts hardened by older anvil versions have fewer records; rollback then uses
what exists (for example an older `.anvil.bak`) or reports a file as "left in
place" rather than guess.

## Look before you trust it

```bash
anvil rollback -c harden.toml --dry-run        # the exact script, nothing connects
ssh admin@host 'sudo ls /var/lib/anvil/; sudo find /etc -name "*.anvil.bak"'
```

`/var/lib/anvil/runs/` keeps a manifest per module and run: every file it
created or modified and every command it ran, with a timestamp.

## Next

- [03_operations.md](03_operations.md): fleets, drift, moving the SSH port, CI gates.
- [04_modules.md](04_modules.md): what each module changes, and which files it owns.
