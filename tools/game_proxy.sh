#!/bin/bash
# Route the game family's TCP through the TLS recording proxy until Ctrl-C/SIGTERM.
# Every TCP connection from the selected Wine prefixes is forwarded unchanged and
# recorded; TLS ClientHellos are decoded on any port. UDP 443 is refused by default
# so Chromium falls back to TCP TLS (CS_ALLOW_QUIC=1 lets it through uncaptured).
#
#   tools/game_proxy.sh
#
# Environment:
#   CS_WINEPREFIX   colon-separated prefixes (default ~/.wine-nexon:~/.wine-nexon-2)
#   CS_PROXY_PORT   local proxy port (default 18400)
#   CS_PROXY_PORTS  additional TCP destination ports redirected for every process
#                   (default 443, catching connections made before Wine adoption)
#   CS_ALLOW_QUIC   1 permits UDP 443 instead of forcing TCP fallback
#
# Requires sudo, nft, systemd-run, setpriv, ss, and Wine. The first Ctrl-C removes
# redirection and lets open connections finish; a second cuts them. If the proxy dies
# while redirection exists, new game connections fail closed; rerun this script or
# `sudo nft delete table ip tls13_proxy` to clear them.
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PORTS=${CS_PROXY_PORTS:-443}
PORT=${CS_PROXY_PORT:-18400}
IFS=: read -ra PREFIX_LIST <<< "${CS_WINEPREFIX:-$HOME/.wine-nexon:$HOME/.wine-nexon-2}"
PREFIX=$(for p in "${PREFIX_LIST[@]}"; do realpath -m "$p"; done | paste -sd'|')
WINESERVER=$(command -v wineserver) || { echo "wineserver is not in PATH" >&2; exit 1; }
WINE_DIR=$(dirname "$(dirname "$(realpath "$WINESERVER")")")
MARK=0x1313
STAMP=$(date +%Y%m%d-%H%M%S)
RECORDING="$ROOT/captures/proxy-$STAMP.jsonl"
SCOPE=tls13-game-$STAMP.scope
CGROUP_REL="user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice/$SCOPE"
CGROUP="/sys/fs/cgroup/$CGROUP_REL"
QUIC_RULE="socket cgroupv2 level 5 \"$CGROUP_REL\" udp dport 443 reject"
[[ ${CS_ALLOW_QUIC:-0} == 1 ]] && QUIC_RULE=""
PYTHON="$ROOT/.venv/bin/python"
[[ -x $PYTHON ]] || PYTHON=python3
(( $# == 0 )) || { echo "Usage: tools/game_proxy.sh" >&2; exit 2; }

say() { echo "$(date '+%F %T') $*" >&2; }
sudo nft delete table ip tls13_proxy 2>/dev/null || true
# An empty NAT chain preserves translation for already-open connections across restarts.
sudo nft list table ip tls13_nat_keep >/dev/null 2>&1 || sudo nft -f - <<'KEEP'
table ip tls13_nat_keep {
    chain keep { type nat hook output priority 100; policy accept; }
}
KEEP
sudo nft delete table inet tls13_capture 2>/dev/null || true
mkdir -p "$ROOT/captures"
cd "$ROOT"
PIDS=()
stop() {
    trap - EXIT INT TERM
    sudo nft delete table ip tls13_proxy 2>/dev/null && say "redirect removed: new connections go straight to the server"
    sudo nft delete table inet tls13_capture 2>/dev/null || true
    for pid in "${PIDS[@]:1}"; do sudo kill -TERM "$pid" 2>/dev/null || true; done
    sudo kill -TERM "${PIDS[0]}" 2>/dev/null || true
    trap 'say "cutting the connections still open"; sudo kill -TERM "${PIDS[0]}" 2>/dev/null || true' INT TERM
    while kill -0 "${PIDS[0]}" 2>/dev/null; do wait "${PIDS[0]}" 2>/dev/null || true; done
    say "stopped; recording $RECORDING"
}
trap stop EXIT INT TERM

sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups \
    --inh-caps=+net_admin --ambient-caps=+net_admin \
    "$PYTHON" tools/tls13_proxy.py --listen "127.0.0.1:$PORT" --file "$RECORDING" \
    --mark "$MARK" </dev/null &
PIDS+=($!)
for _ in $(seq 50); do
    ss -Hltn "sport = :$PORT" | grep -q . && break
    kill -0 "${PIDS[0]}" 2>/dev/null || { say "the proxy did not start"; exit 1; }
    sleep 0.1
done
ss -Hltn "sport = :$PORT" | grep -q . || { say "the proxy is not listening on $PORT"; exit 1; }

systemd-run --user --scope --unit="$SCOPE" --quiet sleep infinity </dev/null &
PIDS+=($!)
for _ in $(seq 50); do [[ -d $CGROUP ]] && break; sleep 0.1; done
[[ -d $CGROUP ]] || { say "scope $SCOPE was not made"; exit 1; }
adopt() {
    local failed=""
    while sleep 0.5; do
        for env in $(grep -lzE "^WINEPREFIX=($PREFIX)/?$" /proc/[0-9]*/environ 2>/dev/null); do
            pid=${env#/proc/}; pid=${pid%/environ}
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
            [[ $exe == "$WINE_DIR"/* && ${exe##*/} =~ ^(wineserver|wine(64)?(-preloader)?)$ ]] || continue
            grep -qF "$SCOPE" "/proc/$pid/cgroup" 2>/dev/null && continue
            if echo "$pid" > "$CGROUP/cgroup.procs" 2>/dev/null; then
                say "adopted $pid $(cat "/proc/$pid/comm" 2>/dev/null)"
            elif [[ " $failed " != *" $pid "* ]]; then
                failed+=" $pid"
                say "COULD NOT ADOPT $pid: only TCP to ports $PORTS is captured"
            fi
        done
    done
}
adopt &
PIDS+=($!)

sudo nft -f - <<EOF
table ip tls13_proxy {
    chain output {
        type nat hook output priority dstnat; policy accept;
        meta mark $MARK return
        ip daddr 127.0.0.0/8 return
        socket cgroupv2 level 5 "$CGROUP_REL" meta l4proto tcp redirect to :$PORT
        tcp dport $PORTS redirect to :$PORT
    }
}
table inet tls13_capture {
    chain output {
        type filter hook output priority filter; policy accept;
        $QUIC_RULE
    }
}
EOF
say "capturing all TCP of $SCOPE and TCP to ports $PORTS through 127.0.0.1:$PORT -> $RECORDING"
say "QUIC $([[ -n $QUIC_RULE ]] && echo refused for TCP fallback || echo allowed but not captured); Ctrl-C stops"
wait "${PIDS[0]}"
