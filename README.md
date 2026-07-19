# SSH Exam Gate

[简体中文](README.zh-CN.md)

SSH Exam Gate places a multiple-choice exam in front of selected OpenSSH
public-key logins. Identity is the requested Unix account plus the SHA256
fingerprint of the presented key. Key comments and email-like labels are
metadata only.

This repository does **not** edit, reload, restart, or otherwise change the live
`sshd`. Installing binaries, running the admin, or creating an Access mapping
does not activate interception. OpenSSH invokes the gate only after an operator
installs and validates the supplied `Match Group` configuration.

## Architecture

```text
SSH public key
  -> OpenSSH AuthorizedKeysCommand (%u, %f, %t, %k)
  -> ssh-exam-key-policy (read-only SQLite policy)
     -> pending: restricted PTY + forced ssh-exam-tui command
     -> passed shell: registered key with normal shell semantics
     -> passed ProxyJump: forwarding only + exact permitopen destinations

Loopback admin -> ssh-exam-admin -> SQLite + atomic JSON quiz bank writes
```

- `ssh-exam-key-policy` fails closed and emits an authorized-keys line only for
  an enabled person, key, and Access mapping.
- `ssh-exam-tui` validates `SUDO_USER`, the mapping username/fingerprint/bank,
  attempt limits, and pass state before writing an attempt.
- `ssh-exam-admin` is server-rendered, CSRF-protected, bilingual, and refuses a
  non-loopback bind address.
- SQLite stores people, keys, mappings, attempts, and person-level pass state.
  Mapping rows select a quiz bank. Existing rows migrate to `legacy`.
- Quiz JSON writes use a same-directory temporary file, sync, and atomic rename.

Pass state remains person-level for backwards compatibility: all enabled keys
and mappings for that person inherit a pass. The selected mapping determines
which bank a pending connection receives.

## Prebuilt Releases

Version tags publish two assets on
[GitHub Releases](https://github.com/huluhuluu/ssh-exam/releases):

- `ssh-exam-<VERSION>-linux-x86_64.tar.gz`
- `SHA256SUMS`

The archive targets Linux x86_64 (`x86_64-unknown-linux-gnu`) and contains the
three stripped binaries, example configuration/banks, deployment snippets,
license, and both READMEs. It contains no database, SSH key, cache, log, or
runtime data.

Verify the download before extracting:

```sh
sha256sum -c SHA256SUMS
tar -xzf ssh-exam-<VERSION>-linux-x86_64.tar.gz
```

Build from source for other architectures or when the release's glibc baseline
does not match the target host.

## Source Build

Use current stable Rust and the committed dependency lockfile:

```sh
cargo test --locked
cargo build --release --locked --bins
```

The release profile enables thin LTO, one codegen unit, aborting panics, and
symbol stripping. Release binaries under `dist/` are ignored in ordinary
commits.

Create the same local package after a release build:

```sh
./scripts/package-release.sh \
  --version <VERSION> \
  --binary-dir target/release \
  --output-dir <OUTPUT_DIR>
```

## Install

Use dedicated service identities. These names are examples; the repository
does not create accounts or groups.

```text
/usr/local/libexec/ssh-exam-key-policy   root:root                  0755
/usr/local/libexec/ssh-exam-tui          root:root                  0755
/usr/local/sbin/ssh-exam-admin           root:root                  0755
/etc/ssh-exam/config.json                root:root                  0644
/etc/ssh-exam/admin-auth.json            ssh-exam-admin:root        0600
/var/lib/ssh-exam                        ssh-exam-admin:ssh-exam-db  2770
/var/lib/ssh-exam/quiz.json              ssh-exam-admin:ssh-exam-db 0640
/var/lib/ssh-exam/banks/*.json           ssh-exam-admin:ssh-exam-db 0640
/var/lib/ssh-exam/gate.db                ssh-exam-admin:ssh-exam-db 0660
```

`ssh-exam-key` needs read-only access to the database and future WAL/SHM files.
`ssh-exam-tui` and `ssh-exam-admin` need database write access. Only the admin
needs create/rename access to the quiz file and bank directory. Do not grant any
of these accounts Docker socket access or Docker group membership.

Copy and edit `examples/config.example.json`. Generate deployment-only admin
authentication values; never deploy the example values:

```sh
printf '%s' '<ADMIN_PASSWORD>' | /usr/local/sbin/ssh-exam-admin hash-password
openssl rand -base64 32
```

Store the first result as `password_hash` and the second as
`session_secret_base64` in `admin-auth.json`.

Initialize or migrate SQLite before activation:

```sh
sudo -u ssh-exam-admin /usr/local/sbin/ssh-exam-admin migrate \
  --config /etc/ssh-exam/config.json
```

## Quiz Banks

`quiz_path` is required and is always available as bank id `legacy`. Existing
single-file configs need no change. To enable catalog mode, set
`quiz_directory` to an absolute directory. Every safe `*.json` filename stem in
that directory becomes a stable bank id, for example `host-ssh.json` becomes
`host-ssh`.

Bank ids contain 1-64 lowercase letters/digits with single internal hyphens.
`legacy` is reserved. Each bank defines:

- title;
- descriptive environment: `host`, `docker`, `network`, or `general`;
- pass threshold and maximum attempts;
- one or more multiple-choice questions.

The admin Exam view lists and selects banks, creates banks, edits settings, and
adds/edits/deletes questions. It rejects deleting the final question.

`tui_language` accepts `en`, `zh`, or `bilingual` and defaults to bilingual.
The TUI localizes gate status and controls, but never translates bank-authored
titles, questions, or choices.

The small banks in `examples/banks/` are educational content only. Environment
metadata does not execute commands, provision hosts, create networks, access
Docker, or start containers.

## Admin Tunnel

The admin listens on loopback only (default `127.0.0.1:8787`). Start the service
from the supplied unit or in the foreground, then open a local SSH tunnel using
the bastion's actual listener port:

```sh
ssh -p <SSH_PORT> -L 8787:127.0.0.1:8787 \
  recovery-admin@bastion.example.org
```

Browse `http://127.0.0.1:8787/`. The language selector is server-rendered and
works without JavaScript. Success messages use a signed one-time flash cookie,
so page URLs remain `/`, `/people`, and `/exam/<BANK_ID>`.

In People, create a person, register each device public key, and add Access
mappings. In Exam, manage the legacy quiz and catalog banks.

## Access Mappings

An Access mapping joins a person or selected device key to:

- an existing Unix login account;
- `Normal shell` or forwarding-only `Shared ProxyJump` access;
- one quiz bank;
- exact forwarding destinations for Shared ProxyJump.

Mappings do **not** configure an SSH listener port. The port in an allowed
destination is the target service port. Normal-shell Unix usernames are
dedicated to one person. Shared ProxyJump usernames may be reused, but wildcard
destinations are rejected.

## SSH Interception And Ports

The gate is port-independent. `deploy/sshd_config.snippet` has no `Port` or
`ListenAddress`. OpenSSH passes `%u` (login), `%f` (fingerprint), `%t` (key
type), and `%k` (base64 key blob) to `AuthorizedKeysCommand`. The helper
validates those values and registered key material before emitting output.

For pending access it emits `restrict,pty` plus a forced TUI command containing
the validated bank and language. After pass it emits either the registered key
for a normal shell or forwarding-only options with exact `permitopen` values.

The example uses:

```text
Match Group ssh-exam-gated
    AuthorizedKeysFile none
    AuthorizedKeysCommand /usr/local/libexec/ssh-exam-key-policy --config /etc/ssh-exam/config.json --username %u --fingerprint %f --key-type %t --key-base64 %k
    AuthorizedKeysCommandUser ssh-exam-key
```

Keep at least one tested recovery account outside `ssh-exam-gated`.

## Isolated Testing

Test with `scripts/isolated-sshd.sh` before changing production configuration.
It writes only below the caller-supplied runtime directory and requires an
explicit unused port. It never reads/edits live `sshd_config` or reloads the
system daemon.

The test Unix account must already exist and have a registered key and Access
mapping in the configured database.

```sh
./scripts/isolated-sshd.sh dry-run \
  --runtime-dir <RUNTIME_DIR> \
  --port <TEST_PORT> \
  --test-user exam-test \
  --app-config /etc/ssh-exam/config.json \
  --policy-binary /usr/local/libexec/ssh-exam-key-policy \
  --command-user ssh-exam-key

sudo ./scripts/isolated-sshd.sh validate \
  --runtime-dir <RUNTIME_DIR> --port <TEST_PORT> \
  --test-user exam-test \
  --app-config /etc/ssh-exam/config.json \
  --policy-binary /usr/local/libexec/ssh-exam-key-policy \
  --command-user ssh-exam-key

sudo ./scripts/isolated-sshd.sh background \
  --runtime-dir <RUNTIME_DIR> --port <TEST_PORT> \
  --test-user exam-test \
  --app-config /etc/ssh-exam/config.json \
  --policy-binary /usr/local/libexec/ssh-exam-key-policy \
  --command-user ssh-exam-key
```

Enroll through a real PTY, then stop and clean only that isolated instance:

```sh
ssh -p <TEST_PORT> -t exam-test@127.0.0.1
sudo ./scripts/isolated-sshd.sh stop --runtime-dir <RUNTIME_DIR>
sudo ./scripts/isolated-sshd.sh cleanup --runtime-dir <RUNTIME_DIR>
```

Use `--listen-address` only for an intentionally isolated listener. Firewall
rules and container port publication remain external deployment concerns.

## Production Activation

1. Keep a tested recovery session open and verify a second recovery login on
   the actual `<SSH_PORT>`. Recovery accounts stay outside the gated group.
2. Install binaries, configuration, state directories, service identities,
   database permissions, and the reviewed sudoers rule. Validate it with
   `visudo -cf deploy/sudoers.snippet`.
3. Start the loopback admin. Register a disposable person/key/mapping and verify
   bank editing.
4. Complete the isolated workflow using the same application configuration.
5. Add only intended accounts to `ssh-exam-gated` and install the reviewed
   `Match Group` snippet. Do not add or change `Port` as part of gate activation.
6. Validate the complete production configuration with `/usr/sbin/sshd -t` and
   inspect the match with `sshd -T -C user=<ACCOUNT>,host=bastion.example.org,addr=<CLIENT_IP>`.
7. Reload, do not restart, system SSH. Test recovery first, then the disposable
   gated account from a new terminal. Keep the original recovery session open.

The repository performs none of these live steps automatically.

## First Enrollment And VS Code

The first enrollment must use a real PTY terminal:

```sh
ssh -p <SSH_PORT> -t person-account@bastion.example.org
# Complete the exam; the connection ends.
ssh -p <SSH_PORT> person-account@bastion.example.org
```

VS Code Remote-SSH generally starts non-PTY exec channels. It should **not** be
expected to display this TUI. Complete the first enrollment with `ssh -t` in a
real terminal. After the person passes, normal VS Code Remote-SSH connections
work with the mapping's shell or forwarding semantics.

For ProxyJump, enroll directly with `ssh -t` first. Then configure the bastion
entry's actual `Port <SSH_PORT>` and use it as the jump host.

## Troubleshooting

- **A normal shell appears instead of the exam:** `AuthorizedKeysCommand` is
  not active for that connection, or the Unix user/key is not registered in an
  enabled Access mapping (or the person already passed). Check the effective
  `Match Group`, `%u/%f/%t/%k` invocation, group membership, mapping, key
  fingerprint, and pass state.
- **Key denied:** compare `ssh-keygen -lf <PUBLIC_KEY_FILE>` with the registered
  fingerprint. Comments and emails do not identify a key.
- **Wrong port:** mappings never choose the listener. Inspect the effective
  `Port`/`ListenAddress`, firewall, or container publication and connect with
  the actual `-p <SSH_PORT>`.
- **No TUI through VS Code or ProxyJump:** enroll directly with `ssh -t`; these
  workflows normally use non-PTY channels.
- **Admin unavailable:** keep it loopback-only and use the local tunnel.
- **Quiz write error:** the admin needs write access to the regular quiz file
  and create/rename access to its parent/catalog directory. Symlinks are
  rejected.

## Rollback

From the still-open recovery session, remove affected users from
`ssh-exam-gated` or remove/comment the gate `Match` block. Validate the complete
configuration with `sshd -t`, then reload SSH. Preserved `AuthorizedKeysFile`
access resumes when the match no longer applies. The database and binaries may
remain in place while access is restored.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked --bins
./scripts/validate-sshd.sh
visudo -cf deploy/sudoers.snippet
```

`scripts/pty-smoke.py` exercises TUI startup, resize, input, and cleanup.
`scripts/benchmark-key-policy.py` reports warm process median and p95; its target
is median below 20 ms and p95 below 50 ms.
