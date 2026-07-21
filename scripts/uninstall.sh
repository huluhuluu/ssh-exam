#!/bin/sh
set -eu

CONFIG_DIR=/etc/ssh-exam
STATE_DIR=/var/lib/ssh-exam
DOC_DIR=/usr/share/doc/ssh-exam
PURGE_CONFIRMATION=DELETE-SSH-EXAM

usage() {
    cat <<'EOF'
Usage: ssh-exam-uninstall [OPTIONS]

Remove installed SSH Exam Gate program files.

Options:
  --purge-data                  Also remove configuration, database, quizzes,
                                service identities, and project groups
  --confirm-purge VALUE         Required with --purge-data; VALUE must be
                                DELETE-SSH-EXAM
  -h, --help                    Show this help

Without --purge-data, /etc/ssh-exam and /var/lib/ssh-exam are preserved for a
later reinstall. The command refuses to run while sshd configuration still
references ssh-exam-key-policy.
EOF
}

die() {
    echo "ssh-exam-uninstall: $*" >&2
    exit 1
}

purge_data=0
confirmation=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --purge-data) purge_data=1; shift ;;
        --confirm-purge)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            confirmation=$2
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"
if [ "$purge_data" -eq 1 ] && [ "$confirmation" != "$PURGE_CONFIRMATION" ]; then
    die "--purge-data requires --confirm-purge $PURGE_CONFIRMATION"
fi

active_pattern='^[[:space:]]*AuthorizedKeysCommand[[:space:]].*ssh-exam-key-policy'
if grep -Eqs "$active_pattern" /etc/ssh/sshd_config 2>/dev/null || \
    grep -REqs "$active_pattern" /etc/ssh/sshd_config.d 2>/dev/null; then
    die "OpenSSH still references ssh-exam-key-policy; remove the reviewed Match block, validate sshd, reload it, and retry"
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now ssh-exam-admin.service >/dev/null 2>&1 || true
fi
rm -f -- /etc/systemd/system/ssh-exam-admin.service /etc/sudoers.d/ssh-exam
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi

rm -f -- /usr/local/libexec/ssh-exam-key-policy \
    /usr/local/libexec/ssh-exam-tui /usr/local/libexec/ssh-exam-install \
    /usr/local/libexec/ssh-exam-isolated \
    /usr/local/sbin/ssh-exam-admin /usr/local/sbin/ssh-exam
rm -rf -- "$DOC_DIR"

if [ "$purge_data" -eq 1 ]; then
    rm -rf -- "$CONFIG_DIR" "$STATE_DIR"
    for user in ssh-exam-key ssh-exam-tui ssh-exam-admin; do
        if id "$user" >/dev/null 2>&1; then
            userdel "$user" || echo "warning: could not remove user $user" >&2
        fi
    done
    for group in ssh-exam-gated ssh-exam-db; do
        if getent group "$group" >/dev/null 2>&1; then
            groupdel "$group" || echo "warning: could not remove group $group" >&2
        fi
    done
    echo "SSH Exam Gate program files and runtime data were removed."
else
    echo "SSH Exam Gate program files were removed."
    echo "Preserved: $CONFIG_DIR and $STATE_DIR"
fi

rm -f -- /usr/local/sbin/ssh-exam-uninstall
