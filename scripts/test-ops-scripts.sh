#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
install_script=$project_dir/scripts/install.sh
uninstall_script=$project_dir/scripts/uninstall.sh
command_script=$project_dir/scripts/ssh-exam.sh

sh -n "$install_script"
sh -n "$uninstall_script"
sh -n "$command_script"
"$install_script" --help >/dev/null
"$uninstall_script" --help >/dev/null
"$command_script" --help >/dev/null

grep -q 'OpenSSH was not modified' "$install_script"
grep -q 'AuthorizedKeysCommand.*ssh-exam-key-policy' "$uninstall_script"
grep -q -- '--confirm-purge DELETE-SSH-EXAM' "$install_script"
if grep -Eq '(cp|install|mv|rm|sed).*/etc/ssh/' "$install_script"; then
    echo "installer must not modify /etc/ssh" >&2
    exit 1
fi
grep -q 'sha256sum' "$install_script"
grep -q 'Preserved:.*CONFIG_DIR.*STATE_DIR' "$uninstall_script"

if "$command_script" --start --stop >/dev/null 2>&1; then
    echo "unified command accepted multiple primary actions" >&2
    exit 1
fi

work_dir=$(mktemp -d)
cleanup() {
    "$command_script" --stop --service-mode none --config "$work_dir/config.json" \
        --admin-binary "$work_dir/fake-admin" --runtime-dir "$work_dir/run" \
        --log-file "$work_dir/admin.log" --run-as "$(id -un)" >/dev/null 2>&1 || true
    rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

printf '{}\n' >"$work_dir/config.json"
cat >"$work_dir/fake-admin" <<'EOF'
#!/bin/sh
trap 'exit 0' TERM INT
while :; do
    sleep 1
done
EOF
chmod 0755 "$work_dir/fake-admin"

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

echo "Operational script checks passed"
