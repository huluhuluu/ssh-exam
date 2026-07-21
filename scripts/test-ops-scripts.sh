#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
install_script=$project_dir/scripts/install.sh
uninstall_script=$project_dir/scripts/uninstall.sh
command_script=$project_dir/scripts/ssh-exam.sh
isolated_script=$project_dir/scripts/isolated-sshd.sh

for readme in "$project_dir/README.md" "$project_dir/README.zh-CN.md"; do
    if grep -Eq '^(curl -fsSL|ssh -p ).*\\$' "$readme"; then
        echo "simple README commands must not use hard line continuations: $readme" >&2
        exit 1
    fi
    if grep -q './scripts/isolated-sshd.sh' "$readme"; then
        echo "README must use the unified ssh-exam --isolated entry point: $readme" >&2
        exit 1
    fi
done

sh -n "$install_script"
sh -n "$uninstall_script"
sh -n "$command_script"
sh -n "$isolated_script"
"$install_script" --help >/dev/null
"$uninstall_script" --help >/dev/null
"$command_script" --help >/dev/null
"$command_script" --isolated --help >/dev/null

grep -q 'OpenSSH was not modified' "$install_script"
grep -q 'AuthorizedKeysCommand.*ssh-exam-key-policy' "$uninstall_script"
grep -q -- '--confirm-purge DELETE-SSH-EXAM' "$install_script"
if grep -Eq '(cp|install|mv|rm|sed).*/etc/ssh/' "$install_script"; then
    echo "installer must not modify /etc/ssh" >&2
    exit 1
fi
grep -q 'sha256sum' "$install_script"
grep -q 'password_shared.*00' "$install_script"
grep -q 'Preserved:.*CONFIG_DIR.*STATE_DIR' "$uninstall_script"
grep -q 'ssh-exam-isolated' "$project_dir/scripts/package-release.sh"
grep -q 'ssh-exam-isolated' "$install_script"
grep -q 'ssh-exam-isolated' "$uninstall_script"
grep -q -- '--username \* --fingerprint SHA256\\:\* --language \*' "$project_dir/deploy/sudoers.snippet"
if grep -q -- '--bank' "$project_dir/deploy/sudoers.snippet"; then
    echo "sudoers snippet contains removed --bank argument" >&2
    exit 1
fi

if "$command_script" --start --stop >/dev/null 2>&1; then
    echo "unified command accepted multiple primary actions" >&2
    exit 1
fi
if "$command_script" --start --isolated cleanup --runtime-dir /tmp/ssh-exam-test >/dev/null 2>&1; then
    echo "unified command accepted isolated mode with another primary action" >&2
    exit 1
fi

work_dir=$(mktemp -d)
foreign_pid=
cleanup() {
    "$command_script" --stop --service-mode none --config "$work_dir/config.json" \
        --admin-binary "$work_dir/fake-admin" --runtime-dir "$work_dir/run" \
        --log-file "$work_dir/admin.log" --run-as "$(id -un)" >/dev/null 2>&1 || true
    if [ -n "$foreign_pid" ]; then
        kill "$foreign_pid" >/dev/null 2>&1 || true
        wait "$foreign_pid" 2>/dev/null || true
    fi
    rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

"$command_script" --isolated cleanup --runtime-dir "$work_dir/isolated" >/dev/null
[ ! -e "$work_dir/isolated" ]
mkdir "$work_dir/archive"
cp "$command_script" "$work_dir/archive/ssh-exam"
cp "$isolated_script" "$work_dir/archive/ssh-exam-isolated"
chmod 0755 "$work_dir/archive/ssh-exam" "$work_dir/archive/ssh-exam-isolated"
"$work_dir/archive/ssh-exam" --isolated cleanup \
    --runtime-dir "$work_dir/archive-isolated" >/dev/null
[ ! -e "$work_dir/archive-isolated" ]

printf '{}\n' >"$work_dir/config.json"
cat >"$work_dir/fake-admin" <<'EOF'
#!/bin/sh
directory=${0%/*}
case "${1:-}" in
    serve)
        trap 'exit 0' TERM INT
        while :; do sleep 1; done
        ;;
    migrate)
        printf '%s\n' "$*" >"$directory/admin-args"
        ;;
    set-admin-password)
        printf '%s\n' "$*" >"$directory/admin-args"
        cat >"$directory/admin-password"
        ;;
    *) exit 64 ;;
esac
EOF
chmod 0755 "$work_dir/fake-admin"

printf '%s' 'replacement-password' >"$work_dir/password"
chmod 0600 "$work_dir/password"
"$command_script" --set-admin-password --config "$work_dir/config.json" \
    --admin-binary "$work_dir/fake-admin" \
    --admin-password-file "$work_dir/password" >/dev/null
[ "$(cat "$work_dir/admin-password")" = replacement-password ]
grep -Fqx "set-admin-password --config $work_dir/config.json" "$work_dir/admin-args"
"$command_script" --migrate --config "$work_dir/config.json" \
    --admin-binary "$work_dir/fake-admin" --run-as "$(id -un)"
grep -Fqx "migrate --config $work_dir/config.json" "$work_dir/admin-args"
if "$command_script" --migrate --config "$work_dir/config.json" \
    --admin-binary "$work_dir/fake-admin" --run-as "$(id -un)" \
    --admin-password-file "$work_dir/password" >/dev/null 2>&1; then
    echo "migrate accepted a password option" >&2
    exit 1
fi
if "$command_script" --set-admin-password --config "$work_dir/config.json" \
    --admin-binary "$work_dir/fake-admin" --run-as "$(id -un)" \
    --admin-password-file "$work_dir/password" --runtime-dir "$work_dir/run" \
    >/dev/null 2>&1; then
    echo "password rotation accepted a runtime option" >&2
    exit 1
fi
chmod 0644 "$work_dir/password"
if "$command_script" --set-admin-password --config "$work_dir/config.json" \
    --admin-binary "$work_dir/fake-admin" \
    --admin-password-file "$work_dir/password" >/dev/null 2>&1; then
    echo "password rotation accepted a group-readable password file" >&2
    exit 1
fi
chmod 0600 "$work_dir/password"
if "$command_script" --start --service-mode none --config "$work_dir/config.json" \
    --admin-binary "$work_dir/fake-admin" --run-as "$(id -un)" \
    --admin-password-file "$work_dir/password" >/dev/null 2>&1; then
    echo "service action accepted a password option" >&2
    exit 1
fi

service_args="--service-mode none --config $work_dir/config.json --admin-binary $work_dir/fake-admin --runtime-dir $work_dir/run --log-file $work_dir/admin.log --run-as $(id -un)"
# The test paths contain no whitespace; splitting is intentional for POSIX sh.
# shellcheck disable=SC2086
"$command_script" --start $service_args >/dev/null
# shellcheck disable=SC2086
"$command_script" --status $service_args >/dev/null
# shellcheck disable=SC2086
"$command_script" --stop $service_args >/dev/null
set +e
# shellcheck disable=SC2086
"$command_script" --status $service_args >/dev/null 2>&1
status=$?
set -e
[ "$status" -eq 3 ] || {
    echo "stopped unified service status should exit 3" >&2
    exit 1
}

printf '{}\n' >"$work_dir/other-config.json"
"$work_dir/fake-admin" serve --config "$work_dir/other-config.json" >/dev/null 2>&1 &
foreign_pid=$!
mkdir -p "$work_dir/run"
printf '%s\n' "$foreign_pid" >"$work_dir/run/admin.pid"
# shellcheck disable=SC2086
"$command_script" --stop $service_args >/dev/null
kill -0 "$foreign_pid" 2>/dev/null || {
    echo "stop killed an admin process using a different config" >&2
    exit 1
}
kill "$foreign_pid"
wait "$foreign_pid" 2>/dev/null || true
foreign_pid=

echo "Operational script checks passed"
