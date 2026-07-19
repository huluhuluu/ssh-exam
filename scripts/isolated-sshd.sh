#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage:
  isolated-sshd.sh ACTION --runtime-dir DIR --test-user USER \
    --app-config FILE --policy-binary FILE [options]

Actions:
  dry-run     Check inputs and port availability without creating files.
  validate    Generate isolated state and run sshd -t.
  foreground  Validate, then run the isolated sshd in the foreground.
  background  Validate, then start sshd and write DIR/sshd.pid.
  stop        Stop the sshd recorded in DIR/sshd.pid.
  cleanup     Stop it if needed and remove only script-created state.

Options:
  --runtime-dir DIR       Absolute caller-owned runtime directory (required).
  --test-user USER        Existing Unix login account to test (required to run).
  --app-config FILE       Absolute SSH Exam Gate config path (required to run).
  --policy-binary FILE    Absolute key-policy binary path (required to run).
  --port PORT             Unused isolated SSH port (required; range: 1024-65535).
  --listen-address ADDR   Listener address (default: 127.0.0.1).
  --command-user USER     Existing AuthorizedKeysCommand user (default: caller).
  --sshd FILE             Absolute sshd path (default: /usr/sbin/sshd).

This script never reads or edits /etc/ssh/sshd_config and never reloads the
system sshd. Cleanup command: isolated-sshd.sh cleanup --runtime-dir DIR
EOF
}

die() {
    echo "isolated-sshd: $*" >&2
    exit 1
}

[ "$#" -ge 1 ] || {
    usage >&2
    exit 2
}

action=$1
shift
runtime_dir=
test_user=
app_config=
policy_binary=
port=
listen_address=127.0.0.1
command_user=$(id -un)
sshd_path=/usr/sbin/sshd

while [ "$#" -gt 0 ]; do
    case "$1" in
        --runtime-dir|--test-user|--app-config|--policy-binary|--port|--listen-address|--command-user|--sshd)
            [ "$#" -ge 2 ] || die "$1 requires a value"
            option=$1
            value=$2
            shift 2
            case "$option" in
                --runtime-dir) runtime_dir=$value ;;
                --test-user) test_user=$value ;;
                --app-config) app_config=$value ;;
                --policy-binary) policy_binary=$value ;;
                --port) port=$value ;;
                --listen-address) listen_address=$value ;;
                --command-user) command_user=$value ;;
                --sshd) sshd_path=$value ;;
            esac
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *) die "unknown option: $1" ;;
    esac
done

case "$action" in
    dry-run|validate|foreground|background|stop|cleanup) ;;
    *) usage >&2; die "unknown action: $action" ;;
esac

[ -n "$runtime_dir" ] || die "--runtime-dir is required"
case "$runtime_dir" in
    /*) ;;
    *) die "--runtime-dir must be absolute" ;;
esac
[ "$runtime_dir" != / ] || die "refusing to use / as the runtime directory"
case "$runtime_dir" in
    *"
"*) die "runtime directory must not contain newlines" ;;
esac

config_file=$runtime_dir/sshd_config
host_key=$runtime_dir/ssh_host_ed25519_key
pid_file=$runtime_dir/sshd.pid
log_file=$runtime_dir/sshd.log

validate_username() {
    label=$1
    value=$2
    printf '%s\n' "$value" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || \
        die "$label must be a valid Unix username"
    getent passwd "$value" >/dev/null || die "$label does not exist: $value"
}

validate_run_inputs() {
    [ -n "$test_user" ] || die "--test-user is required for $action"
    [ -n "$app_config" ] || die "--app-config is required for $action"
    [ -n "$policy_binary" ] || die "--policy-binary is required for $action"
    [ -n "$port" ] || die "--port is required for $action"
    validate_username "--test-user" "$test_user"
    validate_username "--command-user" "$command_user"

    case "$port" in
        *[!0-9]*|'') die "--port must be a number between 1024 and 65535" ;;
    esac
    [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || \
        die "--port must be between 1024 and 65535"
    printf '%s\n' "$listen_address" | grep -Eq '^[0-9A-Fa-f:.]+$' || \
        die "--listen-address must be a numeric IPv4 or IPv6 address"

    for path in "$app_config" "$policy_binary" "$sshd_path"; do
        case "$path" in
            /*) ;;
            *) die "application and daemon paths must be absolute" ;;
        esac
        case "$path" in
            *[!A-Za-z0-9_./:-]*) die "paths must not contain whitespace or sshd metacharacters: $path" ;;
        esac
    done
    [ -r "$app_config" ] || die "application config is not readable: $app_config"
    [ -x "$policy_binary" ] || die "key-policy binary is not executable: $policy_binary"
    [ -x "$sshd_path" ] || die "sshd is not executable: $sshd_path"
}

port_is_free() {
    command -v ss >/dev/null 2>&1 || die "ss is required to check port availability"
    if ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .; then
        die "TCP port $port is already in use"
    fi
}

running_pid() {
    [ -f "$pid_file" ] || return 1
    pid=$(sed -n '1p' "$pid_file")
    case "$pid" in
        *[!0-9]*|'') die "invalid PID file: $pid_file" ;;
    esac
    kill -0 "$pid" 2>/dev/null || return 1
    command_line=$(ps -p "$pid" -o args= 2>/dev/null || true)
    case "$command_line" in
        *"$config_file"*) return 0 ;;
        *) die "PID $pid is not the isolated sshd for $config_file; refusing to signal it" ;;
    esac
}

prepare_state() {
    port_is_free
    if running_pid; then
        die "isolated sshd is already running with PID $pid"
    fi
    if [ -f "$pid_file" ]; then
        rm -f -- "$pid_file"
    fi
    umask 077
    mkdir -p -- "$runtime_dir"
    [ -d "$runtime_dir" ] && [ ! -L "$runtime_dir" ] || \
        die "runtime path must be a real directory: $runtime_dir"
    chmod 0700 -- "$runtime_dir"

    if [ ! -f "$host_key" ]; then
        [ ! -e "$host_key" ] && [ ! -L "$host_key" ] || \
            die "host key path is not a regular file: $host_key"
        ssh-keygen -q -t ed25519 -N '' -f "$host_key"
    fi
    [ -f "$host_key" ] && [ ! -L "$host_key" ] || \
        die "host key must be a regular file: $host_key"

    cat >"$config_file" <<EOF
Port $port
ListenAddress $listen_address
HostKey $host_key
PidFile $pid_file
UsePAM no
StrictModes yes
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AuthorizedKeysFile none
AuthorizedKeysCommand $policy_binary --config $app_config --username %u --fingerprint %f --key-type %t --key-base64 %k
AuthorizedKeysCommandUser $command_user
AllowUsers $test_user
PermitTTY yes
AllowTcpForwarding yes
PermitTunnel no
X11Forwarding no
LogLevel VERBOSE
Subsystem sftp internal-sftp
EOF
    chmod 0600 -- "$config_file"
}

validate_state() {
    "$sshd_path" -t -f "$config_file"
}

stop_daemon() {
    if ! running_pid; then
        if [ -f "$pid_file" ]; then
            rm -f -- "$pid_file"
        fi
        echo "No isolated sshd is running."
        return
    fi
    kill "$pid"
    count=0
    while kill -0 "$pid" 2>/dev/null && [ "$count" -lt 50 ]; do
        sleep 0.1
        count=$((count + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        die "PID $pid did not stop; inspect it before taking further action"
    fi
    rm -f -- "$pid_file"
    echo "Stopped isolated sshd PID $pid."
}

case "$action" in
    dry-run)
        validate_run_inputs
        port_is_free
        echo "Dry run passed. No files were created."
        echo "Runtime: $runtime_dir"
        echo "Listener: $listen_address:$port"
        echo "Test account: $test_user"
        ;;
    validate)
        validate_run_inputs
        prepare_state
        validate_state
        echo "Isolated sshd configuration is valid: $config_file"
        ;;
    foreground)
        validate_run_inputs
        prepare_state
        validate_state
        echo "Starting isolated sshd on $listen_address:$port; press Ctrl-C to stop."
        exec "$sshd_path" -D -e -f "$config_file"
        ;;
    background)
        validate_run_inputs
        prepare_state
        validate_state
        "$sshd_path" -f "$config_file" -E "$log_file"
        count=0
        while [ "$count" -lt 30 ]; do
            if running_pid && ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .; then
                echo "Started isolated sshd PID $pid on $listen_address:$port."
                echo "Stop: $0 stop --runtime-dir $runtime_dir"
                echo "Cleanup: $0 cleanup --runtime-dir $runtime_dir"
                exit 0
            fi
            sleep 0.1
            count=$((count + 1))
        done
        stop_daemon >/dev/null 2>&1 || true
        die "isolated sshd failed to listen; inspect $log_file"
        ;;
    stop)
        stop_daemon
        ;;
    cleanup)
        stop_daemon
        rm -f -- "$config_file" "$host_key" "$host_key.pub" "$log_file" "$pid_file"
        rmdir -- "$runtime_dir" 2>/dev/null || true
        echo "Removed isolated sshd state from $runtime_dir."
        ;;
esac
