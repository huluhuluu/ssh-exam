#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_dir=$(mktemp -d)
cleanup() {
    rm -rf -- "$temporary_dir"
}
trap cleanup EXIT HUP INT TERM

ssh-keygen -q -t ed25519 -N '' -f "$temporary_dir/host_key"

{
    echo "HostKey $temporary_dir/host_key"
    echo "PidFile $temporary_dir/sshd.pid"
    echo "UsePAM no"
    echo "StrictModes yes"
    # Substitute only accounts/paths that intentionally do not exist in the
    # development container. Directive structure and expansion tokens remain.
    sed \
        -e 's#^    AuthorizedKeysCommand /usr/local/libexec/ssh-exam-key-policy#    AuthorizedKeysCommand /bin/true#' \
        -e 's#^    AuthorizedKeysCommandUser ssh-exam-key#    AuthorizedKeysCommandUser nobody#' \
        "$project_dir/deploy/sshd_config.snippet"
} >"$temporary_dir/sshd_config"

/usr/sbin/sshd -t -f "$temporary_dir/sshd_config"
echo "OpenSSH configuration syntax is valid."
