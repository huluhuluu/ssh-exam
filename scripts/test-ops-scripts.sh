#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
install_script=$project_dir/scripts/install.sh
uninstall_script=$project_dir/scripts/uninstall.sh

sh -n "$install_script"
sh -n "$uninstall_script"
"$install_script" --help >/dev/null
"$uninstall_script" --help >/dev/null

grep -q 'OpenSSH was not modified' "$install_script"
grep -q 'AuthorizedKeysCommand.*ssh-exam-key-policy' "$uninstall_script"
grep -q -- '--confirm-purge DELETE-SSH-EXAM' "$install_script"
if grep -Eq '(cp|install|mv|rm|sed).*/etc/ssh/' "$install_script"; then
    echo "installer must not modify /etc/ssh" >&2
    exit 1
fi
grep -q 'sha256sum' "$install_script"
grep -q 'Preserved:.*CONFIG_DIR.*STATE_DIR' "$uninstall_script"

echo "Operational script checks passed"
