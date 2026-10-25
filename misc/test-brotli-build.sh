#!/bin/sh
set -eu

# Run on Linux with both Brotli development packages installed.
pkg-config --exists libbrotlidec libbrotlienc
pkg_config=$(command -v pkg-config)
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${1:?usage: test-brotli-build.sh BUILD_DIRECTORY}

configure() {
    cmake -S "$source_dir" -B "$build_dir" -DBUILD_SHARED_LIBS=ON \
        -DWITH_FUSION=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON "$@"
    cmake --build "$build_dir" --target picotls-core -j 2
    test -s "$build_dir/compile_commands.json"
    readelf -d "$build_dir/libpicotls-core.so" > "$build_dir/brotli-dynamic.txt"
    nm -g "$build_dir/libpicotls-core.so" > "$build_dir/brotli-symbols.txt"
}

check_disabled() {
    if grep -Eq 'PICOTLS_USE_BROTLI|certificate_compression\.c' "$build_dir/compile_commands.json"; then
        echo 'Brotli code was compiled while disabled' >&2
        exit 1
    fi
    if grep -q 'libbrotli' "$build_dir/brotli-dynamic.txt"; then
        echo 'Brotli remains a shared library dependency while disabled' >&2
        exit 1
    fi
    if grep -q 'ptls_decompress_certificate' "$build_dir/brotli-symbols.txt"; then
        echo 'Brotli decompressor remains exported while disabled' >&2
        exit 1
    fi
}

# The default must not depend on pkg-config, even with Brotli installed.
configure -DPKG_CONFIG_EXECUTABLE:FILEPATH=/nonexistent/pkg-config
check_disabled

configure -DWITH_BROTLI=ON -DPKG_CONFIG_EXECUTABLE:FILEPATH="$pkg_config"
grep -q 'certificate_compression\.c' "$build_dir/compile_commands.json"
grep -q 'libbrotlidec' "$build_dir/brotli-dynamic.txt"
grep -q 'ptls_decompress_certificate' "$build_dir/brotli-symbols.txt"

# Cached successful pkg-config probes must not override an explicit OFF.
configure -DWITH_BROTLI=OFF -DPKG_CONFIG_EXECUTABLE:FILEPATH=/nonexistent/pkg-config
check_disabled
echo 'Brotli default, opt-in, and ON-to-OFF reconfiguration checks passed'
