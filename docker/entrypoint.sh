#!/bin/sh
set -eu

fail() {
    echo "fastroll-entrypoint: $*" >&2
    exit 64
}

require_env() {
    name="$1"
    eval "value=\${$name:-}"
    [ -n "$value" ] || fail "$name must be set when JAM_FUZZ is defined"
}

if [ "${JAM_FUZZ+x}" ]; then
    require_env JAM_FUZZ_SPEC
    require_env JAM_FUZZ_DATA_PATH
    require_env JAM_FUZZ_SOCK_PATH

    case "$JAM_FUZZ_SPEC" in
        tiny)
            fastroll_bin="/usr/local/bin/fastroll-tiny"
            ;;
        full)
            fastroll_bin="/usr/local/bin/fastroll-full"
            ;;
        *)
            fail "JAM_FUZZ_SPEC must be either 'tiny' or 'full'"
            ;;
    esac

    if [ -n "${JAM_FUZZ_LOG_LEVEL:-}" ]; then
        case "$JAM_FUZZ_LOG_LEVEL" in
            error|warn|info|debug|trace)
                export RUST_LOG="${RUST_LOG:-$JAM_FUZZ_LOG_LEVEL}"
                ;;
            *)
                fail "JAM_FUZZ_LOG_LEVEL must be one of error, warn, info, debug, trace"
                ;;
        esac
    fi

    mkdir -p "$JAM_FUZZ_DATA_PATH"
    mkdir -p "$(dirname "$JAM_FUZZ_SOCK_PATH")"

    exec "$fastroll_bin" fuzz --socket "$JAM_FUZZ_SOCK_PATH"
fi

exec /usr/local/bin/fastroll-tiny "$@"
