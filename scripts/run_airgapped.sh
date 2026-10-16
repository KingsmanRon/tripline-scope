#!/usr/bin/env bash
# Run a command in a network namespace whose only link is a veth on the local Docker bridge, with no default
# route: it can reach containers on that bridge (e.g. the synthetic SQL Server demo) and nothing else — no
# internet, no host services, no proxy. Proves the product needs no external network. Requires root + iproute2.
set -euo pipefail
NS=tscope-airgap
BR="${DOCKER_BRIDGE:-docker0}"
ADDR="${AIRGAP_ADDR:-172.17.250.250/16}"
cleanup() { ip netns del "$NS" 2>/dev/null || true; ip link del tsag0 2>/dev/null || true; }
trap cleanup EXIT
cleanup
ip netns add "$NS"
ip link add tsag0 type veth peer name tsag1
ip link set tsag1 netns "$NS"
ip link set tsag0 master "$BR" up
ip netns exec "$NS" ip addr add "$ADDR" dev tsag1
ip netns exec "$NS" ip link set tsag1 up
ip netns exec "$NS" ip link set lo up
echo "routes inside the namespace:"; ip netns exec "$NS" ip route
if ip netns exec "$NS" timeout 8 env -u HTTPS_PROXY -u HTTP_PROXY curl -sS -o /dev/null https://pypi.org 2>/dev/null; then
  echo "external network reachable: refusing to run" >&2; exit 2; fi
echo "external network unreachable from the namespace (checked https://pypi.org)"
exec ip netns exec "$NS" env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy "$@"
