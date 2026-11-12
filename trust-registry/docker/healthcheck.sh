#!/bin/bash
# Container health probe: succeeds when GET /health on the registry's REST
# listener answers 200. Uses bash's /dev/tcp so the runtime image needs no
# HTTP client. The port (and address, unless it is a wildcard) comes from
# LISTEN_ADDRESS, as the service reads it. A registry run with
# ENABLE_REST=false has no listener to probe; disable the healthcheck for it
# (`docker run --no-healthcheck`, or `healthcheck: {disable: true}` in compose).
set -euo pipefail

addr="${LISTEN_ADDRESS:-0.0.0.0:3232}"
port="${addr##*:}"
host="${addr%:*}"
host="${host#[}"
host="${host%]}"
case "$host" in
    "" | 0.0.0.0) host=127.0.0.1 ;;
    ::) host=::1 ;;
esac

exec 3<>"/dev/tcp/${host}/${port}"
printf 'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3
IFS= read -r -t 5 status_line <&3
[[ "$status_line" =~ ^HTTP/1\.[01]\ 200\  ]]
