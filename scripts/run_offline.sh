#!/bin/sh
# Run a command with networking disabled: a new, empty network namespace whose only interface is an
# unconfigured loopback. Before running the command it checks that no other interface is visible and
# refuses to run otherwise.
#
#   run_offline.sh COMMAND [ARGS...]
#
# Needs root and unshare(1) (util-linux). Where unprivileged user namespaces are permitted, set
# TSCOPE_OFFLINE_ALLOW_USERNS=1 to use `unshare --user --map-root-user --net` instead (the command then runs
# as a mapped root inside the namespace). Set TSCOPE_OFFLINE_LOOPBACK=1 to bring loopback up (needs ip(8)).
# Otherwise it exits 96 with an explanation; it never silently runs with the network available.
set -eu
if [ $# -eq 0 ]; then
    echo "usage: run_offline.sh COMMAND [ARGS...]" >&2
    exit 2
fi
self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")

if [ "${TSCOPE_OFFLINE_INNER:-}" = "1" ]; then
    unset TSCOPE_OFFLINE_INNER
    others=$(awk -F: 'NR > 2 { gsub(/[ \t]/, "", $1); if ($1 != "lo") print $1 }' /proc/self/net/dev)
    if [ -n "$others" ]; then
        echo "run_offline: refusing to run: network interfaces present: $others" >&2
        exit 97
    fi
    if [ "${TSCOPE_OFFLINE_LOOPBACK:-0}" = "1" ]; then
        ip link set lo up
    fi
    exec "$@"
fi

if [ "$(id -u)" = "0" ] && command -v unshare >/dev/null 2>&1; then
    TSCOPE_OFFLINE_INNER=1 exec unshare --net -- "$self" "$@"
fi
if [ "${TSCOPE_OFFLINE_ALLOW_USERNS:-0}" = "1" ] && command -v unshare >/dev/null 2>&1 \
        && unshare --user --map-root-user --net true 2>/dev/null; then
    TSCOPE_OFFLINE_INNER=1 exec unshare --user --map-root-user --net -- "$self" "$@"
fi
cat >&2 <<'EOF'
run_offline: cannot disable networking for this command.
  It needs root and unshare(1) from util-linux (e.g. sudo scripts/run_offline.sh ...), or
  TSCOPE_OFFLINE_ALLOW_USERNS=1 where unprivileged user namespaces are allowed, or run the whole job
  inside a container started with `docker run --network none`.
EOF
exit 96
