#!/bin/sh
set -eu

REPOSITORY=https://github.com/huluhuluu/ssh-exam
CONFIG_DIR=/etc/ssh-exam
CONFIG_PATH=$CONFIG_DIR/config.json
STATE_DIR=/var/lib/ssh-exam
DOC_DIR=/usr/share/doc/ssh-exam
ADMIN_BINARY=/usr/local/sbin/ssh-exam-admin
UNINSTALL_BINARY=/usr/local/sbin/ssh-exam-uninstall
COMMAND_BINARY=/usr/local/sbin/ssh-exam
INSTALL_HELPER=/usr/local/libexec/ssh-exam-install
ISOLATED_HELPER=/usr/local/libexec/ssh-exam-isolated

usage() {
    cat <<'EOF'
Usage: install.sh [OPTIONS]

Install or upgrade SSH Exam Gate from a verified GitHub release.

Options:
  --version VERSION             Release tag such as v0.4.8 (default: latest)
  --service-mode MODE           auto, systemd, or none (default: auto)
  --admin-bind ADDRESS          Fresh-install loopback bind (default: 127.0.0.1:8787)
  --admin-password-file FILE    Read a fresh-install admin password from FILE
  -h, --help                    Show this help

The installer never edits or reloads OpenSSH. Review the installed deployment
snippets and test a recovery account before activating the gate manually.
EOF
}

die() {
    echo "install.sh: $*" >&2
    exit 1
}

version=latest
service_mode=auto
admin_bind=127.0.0.1:8787
password_file=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|--service-mode|--admin-bind|--admin-password-file)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            option=$1
            value=$2
            shift 2
            case "$option" in
                --version) version=$value ;;
                --service-mode) service_mode=$value ;;
                --admin-bind) admin_bind=$value ;;
                --admin-password-file) password_file=$value ;;
            esac
            ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (for example: sudo sh install.sh)"
[ "$(uname -s)" = Linux ] || die "only Linux is supported by this release installer"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) die "prebuilt releases currently require Linux x86_64" ;;
esac
case "$service_mode" in
    auto|systemd|none) ;;
    *) die "--service-mode must be auto, systemd, or none" ;;
esac
case "$admin_bind" in
    127.0.0.1:*) ;;
    *) die "--admin-bind must use 127.0.0.1 and an explicit port" ;;
esac
admin_port=${admin_bind##*:}
case "$admin_port" in
    ''|*[!0-9]*) die "--admin-bind port must be numeric" ;;
esac
[ "$admin_port" -ge 1 ] 2>/dev/null && [ "$admin_port" -le 65535 ] 2>/dev/null || {
    die "--admin-bind port must be between 1 and 65535"
}

for command in curl sha256sum tar install useradd usermod groupadd getent runuser visudo sudo python3 stat; do
    command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
done

if [ "$service_mode" = auto ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        service_mode=systemd
    else
        service_mode=none
    fi
fi
if [ "$service_mode" = systemd ]; then
    command -v systemctl >/dev/null 2>&1 || die "systemctl is required for systemd mode"
    [ -d /run/systemd/system ] || die "systemd is not running; use --service-mode none"
fi

case "$version" in
    latest)
        latest_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$REPOSITORY/releases/latest")
        version=${latest_url##*/}
        ;;
esac
case "$version" in
    v[0-9]*) ;;
    *) die "invalid release version: $version" ;;
esac
case "$version" in
    *[!A-Za-z0-9._-]*) die "invalid release version: $version" ;;
esac

archive=ssh-exam-${version}-linux-x86_64.tar.gz
release_url=$REPOSITORY/releases/download/$version
work_dir=$(mktemp -d)
tty_settings=
cleanup() {
    if [ -n "$tty_settings" ]; then
        stty "$tty_settings" </dev/tty 2>/dev/null || true
    fi
    rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

echo "Downloading SSH Exam Gate $version"
curl -fsSL "$release_url/$archive" -o "$work_dir/$archive"
curl -fsSL "$release_url/SHA256SUMS" -o "$work_dir/SHA256SUMS"
expected=$(awk -v file="$archive" '$2 == file { print $1 }' "$work_dir/SHA256SUMS")
[ -n "$expected" ] || die "release checksum does not list $archive"
actual=$(sha256sum "$work_dir/$archive" | awk '{ print $1 }')
[ "$actual" = "$expected" ] || die "release archive checksum mismatch"
tar -xzf "$work_dir/$archive" -C "$work_dir"
package_dir=$work_dir/ssh-exam-${version}-linux-x86_64
[ -d "$package_dir" ] || die "release archive has an unexpected layout"

for binary in ssh-exam-key-policy ssh-exam-tui ssh-exam-admin; do
    [ -f "$package_dir/bin/$binary" ] && [ ! -L "$package_dir/bin/$binary" ] || {
        die "release archive is missing $binary"
    }
done
[ -f "$package_dir/uninstall.sh" ] && [ ! -L "$package_dir/uninstall.sh" ] || {
    die "release archive is missing uninstall.sh"
}
[ -f "$package_dir/ssh-exam" ] && [ ! -L "$package_dir/ssh-exam" ] || {
    die "release archive is missing ssh-exam"
}
[ -f "$package_dir/ssh-exam-isolated" ] && [ ! -L "$package_dir/ssh-exam-isolated" ] || {
    die "release archive is missing ssh-exam-isolated"
}

ensure_group() {
    getent group "$1" >/dev/null 2>&1 || groupadd --system "$1"
}

ensure_user() {
    user=$1
    if id "$user" >/dev/null 2>&1; then
        usermod -a -G ssh-exam-db "$user"
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid ssh-exam-db "$user"
    fi
}

ensure_group ssh-exam-db
ensure_group ssh-exam-gated
ensure_user ssh-exam-key
ensure_user ssh-exam-tui
ensure_user ssh-exam-admin

install -d -m 0755 -o root -g root /usr/local/libexec /usr/local/sbin
install -d -m 0755 -o root -g root "$CONFIG_DIR" "$DOC_DIR" "$DOC_DIR/deploy"
install -d -m 2770 -o ssh-exam-admin -g ssh-exam-db "$STATE_DIR" "$STATE_DIR/banks"
install -m 0755 -o root -g root "$package_dir/bin/ssh-exam-key-policy" \
    /usr/local/libexec/ssh-exam-key-policy
install -m 0755 -o root -g root "$package_dir/bin/ssh-exam-tui" \
    /usr/local/libexec/ssh-exam-tui
install -m 0755 -o root -g root "$package_dir/bin/ssh-exam-admin" "$ADMIN_BINARY"
install -m 0755 -o root -g root "$package_dir/uninstall.sh" "$UNINSTALL_BINARY"
install -m 0755 -o root -g root "$package_dir/ssh-exam" "$COMMAND_BINARY"
install -m 0755 -o root -g root "$package_dir/install.sh" "$INSTALL_HELPER"
install -m 0755 -o root -g root "$package_dir/ssh-exam-isolated" "$ISOLATED_HELPER"

install -m 0644 -o root -g root "$package_dir/deploy/sshd_config.snippet" \
    "$package_dir/deploy/sudoers.snippet" "$package_dir/deploy/ssh-exam-admin.service" \
    "$DOC_DIR/deploy/"
install -m 0644 -o root -g root "$package_dir/docs/README.md" \
    "$package_dir/docs/README.zh-CN.md" "$package_dir/docs/LICENSE" "$DOC_DIR/"

if [ ! -e "$CONFIG_PATH" ]; then
    config_temp=$work_dir/config.json
    sudo_path=$(command -v sudo)
    cat >"$config_temp" <<EOF
{
  "database_path": "$STATE_DIR/gate.db",
  "quiz_path": "$STATE_DIR/quiz.json",
  "quiz_directory": "$STATE_DIR/banks",
  "tui_path": "/usr/local/libexec/ssh-exam-tui",
  "tui_run_as": "ssh-exam-tui",
  "sudo_path": "$sudo_path",
  "tui_language": "bilingual",
  "admin_bind": "$admin_bind",
  "admin_auth_path": "$CONFIG_DIR/admin-auth.json",
  "busy_timeout_ms": 5000
}
EOF
    install -m 0644 -o root -g root "$config_temp" "$CONFIG_PATH"
else
    echo "Preserving existing $CONFIG_PATH"
fi

admin_bind=$(python3 - "$CONFIG_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle).get("admin_bind", "127.0.0.1:8787"))
PY
)

if [ ! -e "$STATE_DIR/quiz.json" ]; then
    install -m 0640 -o ssh-exam-admin -g ssh-exam-db \
        "$package_dir/config/quiz.example.json" "$STATE_DIR/quiz.json"
fi
for bank_file in "$package_dir"/config/banks/*.json; do
    destination=$STATE_DIR/banks/${bank_file##*/}
    if [ ! -e "$destination" ]; then
        install -m 0640 -o ssh-exam-admin -g ssh-exam-db "$bank_file" "$destination"
    fi
done

visudo -cf "$package_dir/deploy/sudoers.snippet" >/dev/null
install -d -m 0755 -o root -g root /etc/sudoers.d
install -m 0440 -o root -g root "$package_dir/deploy/sudoers.snippet" \
    /etc/sudoers.d/ssh-exam

read_admin_password() {
    if [ -n "$password_file" ]; then
        [ -f "$password_file" ] && [ ! -L "$password_file" ] && [ -r "$password_file" ] || {
            die "admin password file must be a readable regular non-symlink file"
        }
        password_mode=$(stat -c '%a' "$password_file")
        case "$password_mode" in
            [0-7][0-7][0-7]) ;;
            *) die "admin password file permissions could not be checked" ;;
        esac
        password_shared=${password_mode#?}
        [ "$password_shared" = 00 ] || {
            die "admin password file must not be accessible by group or other users"
        }
        admin_password=$(cat -- "$password_file")
        return
    fi
    [ -r /dev/tty ] || die "fresh install needs a TTY or --admin-password-file"
    tty_settings=$(stty -g </dev/tty)
    printf 'Administrator password: ' >/dev/tty
    stty -echo </dev/tty
    IFS= read -r first </dev/tty
    printf '\nConfirm administrator password: ' >/dev/tty
    IFS= read -r second </dev/tty
    stty "$tty_settings" </dev/tty
    tty_settings=
    printf '\n' >/dev/tty
    [ "$first" = "$second" ] || die "administrator passwords do not match"
    admin_password=$first
}

normalize_state_permissions() {
    chown -R ssh-exam-admin:ssh-exam-db "$STATE_DIR"
    find "$STATE_DIR" -type d -exec chmod 2770 {} +
    find "$STATE_DIR" -type f -name '*.json' -exec chmod 0640 {} +
    find "$STATE_DIR" -type f \( -name '*.db' -o -name '*.db-wal' -o -name '*.db-shm' \) \
        -exec chmod 0660 {} +
}

normalize_state_permissions

if [ ! -e "$CONFIG_DIR/admin-auth.json" ]; then
    admin_password=
    read_admin_password
    printf '%s' "$admin_password" | "$ADMIN_BINARY" init --config "$CONFIG_PATH"
    admin_password=
else
    runuser -u ssh-exam-admin -- "$ADMIN_BINARY" migrate --config "$CONFIG_PATH"
fi

chown ssh-exam-admin:root "$CONFIG_DIR/admin-auth.json"
chmod 0600 "$CONFIG_DIR/admin-auth.json"
normalize_state_permissions

if [ "$service_mode" = systemd ]; then
    install -m 0644 -o root -g root "$package_dir/deploy/ssh-exam-admin.service" \
        /etc/systemd/system/ssh-exam-admin.service
    systemctl daemon-reload
    systemctl enable ssh-exam-admin.service >/dev/null
    systemctl restart ssh-exam-admin.service
    ready=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if curl -fsS "http://$admin_bind/login" >/dev/null; then
            ready=1
            break
        fi
        sleep 1
    done
    [ "$ready" -eq 1 ] || die "admin service did not become ready"
else
    echo "Service mode none: run this as the container service process:"
    echo "  runuser -u ssh-exam-admin -- $ADMIN_BINARY serve --config $CONFIG_PATH"
fi

echo "Installed SSH Exam Gate $version"
echo "OpenSSH was not modified. Review $DOC_DIR/deploy before activation."
echo "Service status: $COMMAND_BINARY --status"
echo "Uninstall program files: $COMMAND_BINARY --uninstall"
echo "Purge all data: $COMMAND_BINARY --purge --confirm-purge DELETE-SSH-EXAM"
