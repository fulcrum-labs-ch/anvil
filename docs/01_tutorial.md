# Tutorial: harden a fresh VPS

From a brand-new Debian/Ubuntu server with root and a password to a CIS Level 1
baseline you can check, re-apply and roll back. Every output below comes from
a real run against a fresh Debian 13 VPS (address and keys replaced).
Allow about 15 minutes.

You need: `anvil` on your machine, the server's root password, and a terminal.

## 1. Get key access

anvil never types passwords; it uses your ssh key (`BatchMode=yes`). Copy
your key to root once. This prompts for the password, so run it in a normal
terminal:

```console
$ ssh-copy-id -i ~/.ssh/id_ed25519.pub root@203.0.113.10
Number of key(s) added: 1
```

Take a snapshot in your provider's panel now if it offers one. Keep a second
SSH session open during the first apply, and know where the provider's web
console is: the root password keeps working there even after SSH passwords
are off.

## 2. First config: admin user, SSH, firewall, updates

Copy [`examples/fresh-vps.toml`](../examples/fresh-vps.toml) and set your
address and public key. It creates `admin` (bash, sudo) *before* sshd turns
root login off.

Check it without connecting, then confirm anvil can reach the server:

```console
$ anvil validate -c fresh-vps.toml
config OK: 1 host(s), 4 module(s) enabled
run order: users -> sshd -> firewall -> updates

$ anvil doctor -c fresh-vps.toml
config + plan: ok (4 modules)
hosts:
  203.0.113.10             ok (reachable)
```

See exactly what would change. On a fresh box every file is new:

```console
$ anvil diff -c fresh-vps.toml
== host 203.0.113.10 ==
  /etc/sudoers.d/admin (users):
      +admin ALL=(ALL) NOPASSWD:ALL
  /etc/ssh/sshd_config.d/05-anvil.conf (sshd):
      +PermitRootLogin no
      +PasswordAuthentication no
      +MaxAuthTries 3
      …
```

anvil does not edit your main `sshd_config`. It writes its own drop-in, a
small extra file that the main config loads. Add `--dry-run` to `apply` to
read the exact bash. Then apply:

```console
$ anvil apply -c fresh-vps.toml
== host 203.0.113.10 ==
  users          changed
  sshd           changed
  firewall       changed
  updates        changed
```

From now on root can't log in. Switch the config to the new account
(`user = "admin"`) and confirm:

```console
$ ssh admin@203.0.113.10 'sudo -n true && echo sudo ok'
sudo ok
$ ssh root@203.0.113.10 true
root@203.0.113.10: Permission denied (publickey).

$ anvil check -c fresh-vps.toml
== host 203.0.113.10 ==
  users          aligned
  sshd           aligned
  firewall       aligned
  updates        aligned
```

Running `apply` again is the idempotency test
([terms](02_concepts.md#terms)): every module reports `ok` and nothing is
touched.

## 3. Second config: the CIS Level 1 baseline

[`examples/fresh-vps-cis.toml`](../examples/fresh-vps-cis.toml) switches to
`profile = "cis-level1"`, a preset that follows the CIS Level 1 baseline (a
public list of hardening rules). It turns on SSH crypto, kernel settings
(sysctl), a module blacklist, PAM password rules and lockout (PAM is the
Linux login system), auditd, fail2ban, `/tmp` noexec, a SUID audit (checks
programs that run with their owner's rights), and security updates. The
example adds a 04:00 reboot window for updates that need one.

PAM changes affect every login, so open a spare session first and keep it
open until you have checked that a fresh login still works. This command
starts one in the background (`-M` makes it the master connection, `-fN`
backgrounds it without a shell):

```console
$ ssh -M -S ~/.ssh/spare.sock -o ControlPersist=60m -fN admin@203.0.113.10
```

Measure first, apply, measure again:

```console
$ anvil score -c fresh-vps.toml       # with [lynis] added
== host 203.0.113.10 == hardening index: 67

$ anvil apply -c fresh-vps-cis.toml
== host 203.0.113.10 ==
  users          ok
  sshd           ok
  ssh_crypto     changed
  kernel         changed
  kernel_modules changed
  pam            changed
  process        changed
  suid           changed
  filesystem     changed
  auditd         changed
  fail2ban       changed
  firewall       ok
  lynis          ok
  updates        changed

$ anvil score -c fresh-vps-cis.toml
== host 203.0.113.10 == hardening index: 75
```

Confirm a fresh login still works, then close the spare session:

```console
$ ssh -o ControlPath=none admin@203.0.113.10 'sudo -n true && echo ok'
ok
$ ssh -S ~/.ssh/spare.sock -O exit admin@203.0.113.10
```

The password policy is enforced by PAM itself, not just written to a config
file. anvil enables it through the distro's `pam-auth-update` and checks the
result, so the stack now reads:

```console
$ ssh admin@203.0.113.10 'grep -E "faillock|pam_unix|pwquality" /etc/pam.d/common-auth /etc/pam.d/common-password'
/etc/pam.d/common-auth:auth	requisite			pam_faillock.so preauth
/etc/pam.d/common-auth:auth	[success=2 default=ignore]	pam_unix.so nullok try_first_pass
/etc/pam.d/common-auth:auth	[default=die]			pam_faillock.so authfail
/etc/pam.d/common-password:password	requisite			pam_pwquality.so retry=3
```

In practice: passwords need 14+ characters with all four character classes,
and five wrong passwords lock an account for 15 minutes (root is never
locked; `faillock --user <name> --reset` unlocks early). SSH key logins are
not affected.

Reboot once and check again. Hardening that breaks at boot is the kind you want
to find now, not at 04:00:

```console
$ ssh admin@203.0.113.10 sudo systemctl reboot
$ anvil check -c fresh-vps-cis.toml       # all 14 aligned
```

## 4. Optional: CrowdSec

CrowdSec reads your logs, detects attacks (SSH brute force and similar) and
bans the attacking IPs at the firewall. Add the section to your section 3 config
(the defaults watch Linux and SSH logs):

```toml
[crowdsec]
```

anvil installs `crowdsec` and `crowdsec-firewall-bouncer` from your
distribution's own archive. They are older than CrowdSec's own releases but
security-maintained by the distro, and anvil never adds a third-party apt
source. The bouncer registers itself with the agent and picks the firewall
backend matching the system (nftables on Debian 13):

```console
$ anvil apply -c fresh-vps-cis.toml --only crowdsec
== host 203.0.113.10 ==
  crowdsec       changed

$ ssh admin@203.0.113.10 'sudo cscli bouncers list; sudo nft list tables'
 Name                 IP Address   Valid   Last API pull          Type                        Auth Type
 FirewallBouncer-…    127.0.0.1    ✔️       2026-10-30T21:28:38Z   crowdsec-firewall-bouncer   api-key
table ip filter
table ip6 filter
table ip crowdsec
table ip6 crowdsec6
```

It runs alongside ufw and fail2ban. To see a ban take effect, ban a
documentation address for two minutes:

```console
$ ssh admin@203.0.113.10 'sudo cscli decisions add --ip 198.51.100.7 --duration 2m'
$ ssh admin@203.0.113.10 'sudo nft list set ip crowdsec crowdsec-blacklists | grep -o 198.51.100.7'
198.51.100.7
$ ssh admin@203.0.113.10 'sudo cscli decisions delete --ip 198.51.100.7'
1 decision(s) deleted
```

`rollback --only crowdsec` leaves it installed and running: it consists only
of installs, which rollback never undoes ([02_concepts.md](02_concepts.md)).

## 5. Watch for drift

If someone changes a managed file by hand, `check` reports it and `diff` shows
exactly what differs, including permissions and line endings, not just
content:

```console
$ ssh admin@203.0.113.10 sudo chmod 600 /etc/fail2ban/jail.d/99-anvil.conf
$ anvil check -c fresh-vps-cis.toml --only fail2ban
  fail2ban       drifted
$ anvil diff -c fresh-vps-cis.toml --only fail2ban
  /etc/fail2ban/jail.d/99-anvil.conf (fail2ban):
      mode: 600 -> 644
$ anvil apply -c fresh-vps-cis.toml --only fail2ban
  fail2ban       changed
```

`check` exits 1 when anything drifted, so it works as a cron job or CI gate:

```console
$ anvil check -c fresh-vps-cis.toml || echo "drift!"
$ anvil score -c fresh-vps-cis.toml --threshold 70
```

## 6. Roll back

`rollback` returns the host to how it was **before anvil first changed it**:
original files back, files anvil created deleted, sysctl values restored,
services reloaded. That is your provider's or your own configuration, not some
generic default ([02_concepts.md](02_concepts.md) explains how). It refuses to remove
the account anvil logs in as, so roll back everything except `users`:

```console
$ anvil rollback -c fresh-vps-cis.toml
error: invalid usage: rollback of `users` would delete the SSH key and sudo rule of "admin", …

$ anvil rollback -c fresh-vps-cis.toml \
    --only sshd,ssh_crypto,kernel,kernel_modules,pam,process,suid,filesystem,auditd,fail2ban,firewall,updates
```

Rolling back `sshd` re-allows root and password login at once, if that was the
original config. The firewall stays on, and whatever port sshd listens on stays
open. Rolling back `pam` removes the lockout from the PAM stack; the
`libpam-pwquality` package stays installed, with its default policy. Modules
can be rolled back one at a time: `pam` and `process` share `/etc/login.defs`,
but each restores only its own lines. Re-apply to harden again. Details and limits:
[03_operations.md](03_operations.md#rolling-back).

## Next

- [02_concepts.md](02_concepts.md): what anvil changes and how rollback undoes it.
- [03_operations.md](03_operations.md): fleets, moving the SSH port, CI gates.
- [04_modules.md](04_modules.md): every module, and the files each one owns.
