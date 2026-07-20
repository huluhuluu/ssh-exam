#!/bin/sh
set -eu

REPOSITORY=https://github.com/huluhuluu/ssh-exam
DEFAULT_CONFIG=/etc/ssh-exam/config.json
DEFAULT_ADMIN_BINARY=/usr/local/sbin/ssh-exam-admin
DEFAULT_RUNTIME_DIR=/run/ssh-exam
UNINSTALL_BINARY=/usr/local/sbin/ssh-exam-uninstall

usage() {
    cat <<'EOF'
Usage: ssh-exam ACTION [OPTIONS]

Primary actions (choose exactly one):
  --install, install       Install the selected verified release
  --upgrade, upgrade       Upgrade through the same idempotent installer
  --uninstall, uninstall   Remove program files and preserve runtime data
  --purge, purge           Remove program files and explicitly confirmed data
  --migrate, migrate       Apply database migrations
  --set-admin-password     Replace the administrator password
  --start, start           Start the admin service
  --stop, stop             Stop the admin service
  --restart, restart       Restart the admin service
  --status, status         Report whether the admin service is running
  --serve, serve           Run the admin service in the foreground
  --version                Show the installed binary version

Install/upgrade options:
  --release VERSION             Release tag such as v0.4.7 (default: latest)
  --service-mode MODE           auto, systemd, or none (default: auto)
  --admin-bind ADDRESS          Fresh-install loopback bind
  --admin-password-file FILE    Fresh-install or replacement password file

Purge option:
  --confirm-purge VALUE         Must be DELETE-SSH-EXAM

Admin/service options:
  --config PATH                 Application config path
  --admin-binary PATH           ssh-exam-admin binary path
  --run-as USER                 Admin/service identity

Non-systemd service options:
  --runtime-dir PATH            PID/log directory for non-systemd mode
  --log-file PATH               Non-systemd log path

The command never edits or reloads OpenSSH.
EOF
}

die() {
    echo "ssh-exam: $*" >&2
    exit 1
}

action=
release=latest
service_mode=auto
admin_bind=127.0.0.1:8787
password_file=
admin_password=
confirmation=
config=$DEFAULT_CONFIG
admin_binary=$DEFAULT_ADMIN_BINARY
runtime_dir=$DEFAULT_RUNTIME_DIR
log_file=
run_as=
install_options=0
password_options=0
purge_options=0
service_options=0
runtime_options=0
service_mode_set=0
tty_settings=

set_action() {
    [ -z "$action" ] || die "choose exactly one primary action"
    action=$1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --install|install) set_action install; shift ;;
        --upgrade|upgrade) set_action upgrade; shift ;;
        --uninstall|uninstall) set_action uninstall; shift ;;
        --purge|purge) set_action purge; shift ;;
        --migrate|migrate) set_action migrate; shift ;;
        --set-admin-password|set-admin-password) set_action set_admin_password; shift ;;
        --start|start) set_action start; shift ;;
        --stop|stop) set_action stop; shift ;;
        --restart|restart) set_action restart; shift ;;
        --status|status) set_action status; shift ;;
        --serve|serve) set_action serve; shift ;;
        --version) set_action version; shift ;;
        --release|--service-mode|--admin-bind|--admin-password-file|--confirm-purge|--config|--admin-binary|--runtime-dir|--log-file|--run-as)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            option=$1
            value=$2
            shift 2
            case "$option" in
                --release) release=$value; install_options=1 ;;
                --service-mode) service_mode=$value; service_mode_set=1 ;;
                --admin-bind) admin_bind=$value; install_options=1 ;;
                --admin-password-file) password_file=$value; password_options=1 ;;
                --confirm-purge) confirmation=$value; purge_options=1 ;;
                --config) config=$value; service_options=1 ;;
                --admin-binary) admin_binary=$value; service_options=1 ;;
                --runtime-dir) runtime_dir=$value; service_options=1; runtime_options=1 ;;
                --log-file) log_file=$value; service_options=1; runtime_options=1 ;;
                --run-as) run_as=$value; service_options=1 ;;
            esac
            ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

[ -n "$action" ] || { usage >&2; exit 2; }
case "$service_mode" in
    auto|systemd|none) ;;
    *) die "--service-mode must be auto, systemd, or none" ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || true)

resolve_release() {
    case "$release" in
        latest)
            latest_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$REPOSITORY/releases/latest")
            release=${latest_url##*/}
            ;;
    esac
    case "$release" in
        v[0-9]*) ;;
        *) die "invalid release version: $release" ;;
    esac
    case "$release" in
        *[!A-Za-z0-9._-]*) die "invalid release version: $release" ;;
    esac
}

run_installer() {
    [ "$purge_options" -eq 0 ] && [ "$service_options" -eq 0 ] || {
        die "install/upgrade accepts only install options"
    }
    for command in curl sha256sum awk mktemp; do
        command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
    done
    resolve_release
    work_dir=$(mktemp -d)
    trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM
    release_url=$REPOSITORY/releases/download/$release
    curl -fsSL "$release_url/install.sh" -o "$work_dir/install.sh"
    curl -fsSL "$release_url/SHA256SUMS" -o "$work_dir/SHA256SUMS"
    expected=$(awk '$2 == "install.sh" { print $1 }' "$work_dir/SHA256SUMS")
    [ -n "$expected" ] || die "release checksum does not list install.sh"
    actual=$(sha256sum "$work_dir/install.sh" | awk '{ print $1 }')
    [ "$actual" = "$expected" ] || die "installer checksum mismatch"
    set -- --version "$release" --service-mode "$service_mode" --admin-bind "$admin_bind"
    if [ -n "$password_file" ]; then
        set -- "$@" --admin-password-file "$password_file"
    fi
    sh "$work_dir/install.sh" "$@"
}

find_uninstaller() {
    if [ -x "$UNINSTALL_BINARY" ]; then
        uninstaller=$UNINSTALL_BINARY
    elif [ -n "$script_dir" ] && [ -f "$script_dir/uninstall.sh" ] && [ ! -L "$script_dir/uninstall.sh" ]; then
        uninstaller=$script_dir/uninstall.sh
    else
        die "uninstaller is not installed"
    fi
}

run_uninstaller() {
    [ "$install_options" -eq 0 ] && [ "$password_options" -eq 0 ] && \
        [ "$service_options" -eq 0 ] && [ "$service_mode_set" -eq 0 ] || {
        die "uninstall/purge does not accept install or service options"
    }
    find_uninstaller
    if [ "$action" = purge ]; then
        [ "$purge_options" -eq 1 ] || die "--purge requires --confirm-purge DELETE-SSH-EXAM"
        exec sh "$uninstaller" --purge-data --confirm-purge "$confirmation"
    fi
    [ "$purge_options" -eq 0 ] || die "--confirm-purge requires --purge"
    exec sh "$uninstaller"
}

validate_command_paths() {
    [ -f "$config" ] && [ ! -L "$config" ] || die "config must be a regular non-symlink file: $config"
    [ -f "$admin_binary" ] && [ ! -L "$admin_binary" ] && [ -x "$admin_binary" ] || {
        die "admin binary must be a regular executable: $admin_binary"
    }
    admin_binary=$(readlink -f "$admin_binary")
    config=$(readlink -f "$config")
}

validate_service_options() {
    [ "$install_options" -eq 0 ] && [ "$password_options" -eq 0 ] && \
        [ "$purge_options" -eq 0 ] || {
        die "service actions accept only service options"
    }
}

validate_service_paths() {
    validate_command_paths
    case "$runtime_dir" in /*) ;; *) die "--runtime-dir must be absolute" ;; esac
    if [ -n "$log_file" ]; then
        case "$log_file" in /*) ;; *) die "--log-file must be absolute" ;; esac
    else
        log_file=$runtime_dir/admin.log
    fi
    pid_file=$runtime_dir/admin.pid
}

resolve_admin_run_as() {
    if [ -z "$run_as" ]; then
        if [ "$action" = migrate ] && [ "$(id -u)" -eq 0 ] && id ssh-exam-admin >/dev/null 2>&1; then
            run_as=ssh-exam-admin
        else
            run_as=$(id -un)
        fi
    fi
    id "$run_as" >/dev/null 2>&1 || die "admin user does not exist: $run_as"
    if [ "$run_as" != "$(id -un)" ]; then
        [ "$(id -u)" -eq 0 ] || die "changing --run-as requires root"
        command -v runuser >/dev/null 2>&1 || die "runuser is required to change --run-as"
    fi
}

run_admin_binary() {
    if [ "$run_as" = "$(id -un)" ]; then
        "$admin_binary" "$@"
    else
        runuser -u "$run_as" -- "$admin_binary" "$@"
    fi
}

restore_tty() {
    if [ -n "$tty_settings" ]; then
        stty "$tty_settings" </dev/tty 2>/dev/null || true
        tty_settings=
    fi
}

read_replacement_password() {
    if [ -n "$password_file" ]; then
        [ -f "$password_file" ] && [ ! -L "$password_file" ] && [ -r "$password_file" ] || {
            die "admin password file must be a readable regular non-symlink file"
        }
        command -v stat >/dev/null 2>&1 || die "stat is required to validate the password file"
        password_mode=$(stat -c '%a' "$password_file")
        case "$password_mode" in
            [0-7][0-7][0-7]) ;;
            *) die "admin password file permissions could not be checked" ;;
        esac
        password_shared=${password_mode#?}
        case "$password_shared" in
            00) ;;
            *) die "admin password file must not be accessible by group or other users" ;;
        esac
        admin_password=$(cat -- "$password_file")
        return
    fi
    [ -r /dev/tty ] || die "password rotation needs a TTY or --admin-password-file"
    command -v stty >/dev/null 2>&1 || die "stty is required for interactive password input"
    tty_settings=$(stty -g </dev/tty)
    trap 'restore_tty' EXIT
    trap 'restore_tty; exit 1' HUP INT TERM
    printf 'New administrator password: ' >/dev/tty
    stty -echo </dev/tty
    IFS= read -r first </dev/tty
    printf '\nConfirm administrator password: ' >/dev/tty
    IFS= read -r second </dev/tty
    restore_tty
    trap - EXIT HUP INT TERM
    printf '\n' >/dev/tty
    [ "$first" = "$second" ] || die "administrator passwords do not match"
    admin_password=$first
}

run_admin_action() {
    [ "$install_options" -eq 0 ] && [ "$purge_options" -eq 0 ] && \
        [ "$runtime_options" -eq 0 ] && [ "$service_mode_set" -eq 0 ] || {
        die "admin actions accept only admin options"
    }
    validate_command_paths
    resolve_admin_run_as
    case "$action" in
        migrate)
            [ "$password_options" -eq 0 ] || die "--admin-password-file requires --set-admin-password or --install"
            run_admin_binary migrate --config "$config"
            ;;
        set_admin_password)
            read_replacement_password
            if printf '%s' "$admin_password" | \
                run_admin_binary set-admin-password --config "$config"; then
                result=0
            else
                result=$?
            fi
            admin_password=
            [ "$result" -eq 0 ] || return "$result"
            echo "Restart the admin service to load the new password and invalidate existing sessions."
            ;;
    esac
}

resolve_service_mode() {
    if [ "$action" = serve ]; then
        service_mode=none
        return
    fi
    if [ "$service_mode" = auto ]; then
        if [ "$service_options" -eq 0 ] && command -v systemctl >/dev/null 2>&1 && \
            [ -d /run/systemd/system ] && systemctl cat ssh-exam-admin.service >/dev/null 2>&1; then
            service_mode=systemd
        else
            service_mode=none
        fi
    fi
    if [ "$service_mode" = systemd ] && [ "$service_options" -ne 0 ]; then
        die "custom service paths require --service-mode none"
    fi
}

process_matches() {
    candidate=$1
    case "$candidate" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$candidate" 2>/dev/null || return 1
    [ -r "/proc/$candidate/cmdline" ] || return 1
    expected=$(printf '%s\nserve\n--config\n%s' "$admin_binary" "$config")
    actual=$(tr '\000' '\n' <"/proc/$candidate/cmdline")
    case "$actual" in
        "$expected"|*"
$expected") return 0 ;;
        *) return 1 ;;
    esac
}

read_managed_pid() {
    managed_pid=
    if [ -f "$pid_file" ] && [ ! -L "$pid_file" ]; then
        candidate=$(sed -n '1p' "$pid_file")
        if process_matches "$candidate"; then
            managed_pid=$candidate
        else
            rm -f -- "$pid_file"
        fi
    fi
}

prepare_runtime() {
    [ ! -L "$runtime_dir" ] || die "runtime directory must not be a symlink"
    if [ -z "$run_as" ]; then
        if [ "$(id -u)" -eq 0 ] && id ssh-exam-admin >/dev/null 2>&1; then
            run_as=ssh-exam-admin
        else
            run_as=$(id -un)
        fi
    fi
    id "$run_as" >/dev/null 2>&1 || die "service user does not exist: $run_as"
    if [ "$(id -u)" -eq 0 ]; then
        group=$(id -gn "$run_as")
        install -d -m 0755 -o "$run_as" -g "$group" "$runtime_dir"
        touch "$log_file"
        chown "$run_as:$group" "$log_file"
    else
        [ "$run_as" = "$(id -un)" ] || die "changing --run-as requires root"
        mkdir -p -- "$runtime_dir"
        touch "$log_file"
    fi
}

start_fallback() {
    prepare_runtime
    read_managed_pid
    if [ -n "$managed_pid" ]; then
        echo "ssh-exam admin is already running (pid $managed_pid)"
        return
    fi
    command -v nohup >/dev/null 2>&1 || die "nohup is required for background mode"
    launch='pid_file=$1; binary=$2; config=$3; printf "%s\n" "$$" >"$pid_file.tmp"; mv -f "$pid_file.tmp" "$pid_file"; exec "$binary" serve --config "$config"'
    if [ "$run_as" = "$(id -un)" ]; then
        nohup sh -c "$launch" sh "$pid_file" "$admin_binary" "$config" >>"$log_file" 2>&1 </dev/null &
    else
        nohup runuser -u "$run_as" -- sh -c "$launch" sh "$pid_file" "$admin_binary" "$config" >>"$log_file" 2>&1 </dev/null &
    fi
    started=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sleep 1
        read_managed_pid
        if [ -n "$managed_pid" ]; then
            started=1
            break
        fi
    done
    [ "$started" -eq 1 ] || die "admin service did not start; inspect $log_file"
    sleep 1
    process_matches "$managed_pid" || die "admin service exited during startup; inspect $log_file"
    echo "ssh-exam admin started (pid $managed_pid)"
}

stop_fallback() {
    read_managed_pid
    if [ -z "$managed_pid" ]; then
        echo "ssh-exam admin is not running"
        return
    fi
    kill "$managed_pid"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        process_matches "$managed_pid" || break
        sleep 1
    done
    if process_matches "$managed_pid"; then
        kill -KILL "$managed_pid"
    fi
    rm -f -- "$pid_file"
    echo "ssh-exam admin stopped"
}

run_service_action() {
    validate_service_options
    resolve_service_mode
    if [ "$service_mode" = systemd ]; then
        command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || {
            die "systemd is not running; use --service-mode none"
        }
        case "$action" in
            start|stop|restart) systemctl "$action" ssh-exam-admin.service ;;
            status) systemctl status --no-pager ssh-exam-admin.service ;;
        esac
        return
    fi
    validate_service_paths
    case "$action" in
        start) start_fallback ;;
        stop) stop_fallback ;;
        restart) stop_fallback; start_fallback ;;
        status)
            read_managed_pid
            if [ -n "$managed_pid" ]; then
                echo "ssh-exam admin is running (pid $managed_pid)"
            else
                echo "ssh-exam admin is not running"
                exit 3
            fi
            ;;
        serve)
            if [ -z "$run_as" ]; then
                if [ "$(id -u)" -eq 0 ] && id ssh-exam-admin >/dev/null 2>&1; then
                    run_as=ssh-exam-admin
                else
                    run_as=$(id -un)
                fi
            fi
            id "$run_as" >/dev/null 2>&1 || die "service user does not exist: $run_as"
            if [ "$run_as" = "$(id -un)" ]; then
                exec "$admin_binary" serve --config "$config"
            fi
            [ "$(id -u)" -eq 0 ] || die "changing --run-as requires root"
            exec runuser -u "$run_as" -- "$admin_binary" serve --config "$config"
            ;;
    esac
}

case "$action" in
    install|upgrade) run_installer ;;
    uninstall|purge) run_uninstaller ;;
    migrate|set_admin_password) run_admin_action ;;
    start|stop|restart|status|serve) run_service_action ;;
    version)
        [ "$install_options" -eq 0 ] && [ "$password_options" -eq 0 ] && [ "$purge_options" -eq 0 ] && \
            [ "$service_options" -eq 0 ] && [ "$service_mode_set" -eq 0 ] || {
            die "--version does not accept additional options"
        }
        if [ -x "$admin_binary" ]; then
            exec "$admin_binary" --version
        fi
        echo "ssh-exam lifecycle command"
        ;;
esac
