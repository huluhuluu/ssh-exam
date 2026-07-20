#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage: package-release.sh --version VERSION --binary-dir DIR --output-dir DIR

Packages stripped Linux x86_64 release binaries, installation scripts,
examples, deployment snippets, operator documentation, and the license. It
never copies databases, keys, caches, logs, or runtime state.
EOF
}

version=
binary_dir=
output_dir=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|--binary-dir|--output-dir)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            option=$1
            value=$2
            shift 2
            case "$option" in
                --version) version=$value ;;
                --binary-dir) binary_dir=$value ;;
                --output-dir) output_dir=$value ;;
            esac
            ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

[ -n "$version" ] && [ -n "$binary_dir" ] && [ -n "$output_dir" ] || {
    usage >&2
    exit 2
}
case "$version" in
    *[!A-Za-z0-9._-]*|''|.|..) echo "invalid release version" >&2; exit 2 ;;
esac

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
staging_dir=$(mktemp -d)
package_name=ssh-exam-${version}-linux-x86_64
package_root=$staging_dir/$package_name
cleanup() {
    rm -rf -- "$staging_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p -- "$package_root/bin" "$package_root/config/banks" \
    "$package_root/deploy" "$package_root/docs" "$output_dir"

for binary in ssh-exam-key-policy ssh-exam-tui ssh-exam-admin; do
    source_path=$binary_dir/$binary
    [ -f "$source_path" ] && [ ! -L "$source_path" ] && [ -x "$source_path" ] || {
        echo "missing regular executable: $source_path" >&2
        exit 1
    }
    file "$source_path" | grep -Eq 'ELF 64-bit.*x86-64' || {
        echo "release input is not a Linux x86_64 ELF binary: $source_path" >&2
        exit 1
    }
    cp -- "$source_path" "$package_root/bin/$binary"
    strip --strip-all "$package_root/bin/$binary"
done

cp -- "$project_dir/examples/config.example.json" \
    "$project_dir/examples/admin-auth.example.json" \
    "$project_dir/examples/quiz.example.json" "$package_root/config/"
cp -- "$project_dir/examples/banks/"*.json "$package_root/config/banks/"
cp -- "$project_dir/deploy/ssh-exam-admin.service" \
    "$project_dir/deploy/sshd_config.snippet" \
    "$project_dir/deploy/sudoers.snippet" "$package_root/deploy/"
cp -- "$project_dir/README.md" "$project_dir/README.zh-CN.md" \
    "$project_dir/LICENSE" "$package_root/docs/"
cp -- "$project_dir/scripts/install.sh" "$package_root/install.sh"
cp -- "$project_dir/scripts/uninstall.sh" "$package_root/uninstall.sh"
cp -- "$project_dir/scripts/ssh-exam.sh" "$package_root/ssh-exam"
chmod 0755 "$package_root/install.sh" "$package_root/uninstall.sh" \
    "$package_root/ssh-exam"

archive=$output_dir/$package_name.tar.gz
[ ! -e "$archive" ] && [ ! -e "$output_dir/SHA256SUMS" ] && \
    [ ! -e "$output_dir/install.sh" ] && [ ! -e "$output_dir/uninstall.sh" ] && \
    [ ! -e "$output_dir/ssh-exam" ] || {
    echo "release output already exists in $output_dir" >&2
    exit 1
}
tar -czf "$archive" -C "$staging_dir" "$package_name"
cp -- "$project_dir/scripts/install.sh" "$output_dir/install.sh"
cp -- "$project_dir/scripts/uninstall.sh" "$output_dir/uninstall.sh"
cp -- "$project_dir/scripts/ssh-exam.sh" "$output_dir/ssh-exam"
chmod 0755 "$output_dir/install.sh" "$output_dir/uninstall.sh" "$output_dir/ssh-exam"
(
    cd -- "$output_dir"
    sha256sum "$package_name.tar.gz" ssh-exam install.sh uninstall.sh >SHA256SUMS
)
echo "Created $archive"
echo "Created $output_dir/install.sh"
echo "Created $output_dir/uninstall.sh"
echo "Created $output_dir/ssh-exam"
echo "Created $output_dir/SHA256SUMS"
