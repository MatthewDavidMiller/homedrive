#!/bin/bash
# What the sync client costs as a real process: its memory and CPU across a
# first sync, an idle daemon, an edit, the GUI left open, and a transfer each
# way. `make bench` shares one process with the server, so it cannot show the
# client's own figures; here the two are separate programs over loopback.
#
# Usage: make bench-daemon
#        ./scripts/toolbox.sh env HD_BENCH_FILES=N HD_BENCH_IDLE=SECONDS \
#            ./scripts/bench-daemon.sh [DIRECTORY OF BINARIES]
#
# The idle stretch is longer than the daemon's 5-minute full scan, so the
# figure includes one. Timings prove nothing on a busy machine.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$(cd "${1:-${PROJECT_ROOT}/target/release}" && pwd)"
FILES="${HD_BENCH_FILES:-50000}"
IDLE="${HD_BENCH_IDLE:-320}"
PORT=18080
WORK="${PROJECT_ROOT}/target/bench-daemon/$$"
TICK_HZ="$(getconf CLK_TCK)"

mkdir -p "${WORK}/local" "${WORK}/store"
export HOME="${WORK}/home" XDG_CONFIG_HOME="${WORK}/config" XDG_STATE_HOME="${WORK}/state"
export HOMEDRIVE_PASSWORD="a bench password" HOMEDRIVE_NO_BROWSER=1
mkdir -p "${HOME}"

pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "${pid}" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "${WORK}"
}
trap cleanup EXIT

# User plus system clock ticks of a process, all its threads included.
ticks() { awk '{ sub(/^.*\) /, ""); print $12 + $13 }' "/proc/$1/stat"; }

# Times its threads gave up the CPU willingly: its wake-ups, near enough.
wakeups() {
    cat "/proc/$1"/task/*/status | awk '/^voluntary_ctxt_switches/ { n += $2 } END { print n }'
}

memory_mb() { awk -v f="$2:" '$1 == f { printf "%.1f", $2 / 1024 }' "/proc/$1/status"; }

seconds() { awk -v t="$1" -v hz="${TICK_HZ}" 'BEGIN { printf "%.2f", t / hz }'; }

# Waits until a process has used no CPU for $2 seconds.
settle() {
    local pid="$1" quiet="$2" last now still=0
    last="$(ticks "${pid}")"
    while ((still < quiet)); do
        sleep 1
        now="$(ticks "${pid}")"
        if [[ "${now}" == "${last}" ]]; then still=$((still + 1)); else still=0; fi
        last="${now}"
    done
}

start_daemon() {
    "${BIN}/homedrive" daemon "$@" >"${WORK}/daemon.log" 2>&1 &
    daemon=$!
    pids+=("${daemon}")
}

stop_daemon() {
    kill "${daemon}"
    wait "${daemon}" 2>/dev/null || true
}

report() {
    printf '%-34s %8s s CPU %10s wake-ups %8s MB now %8s MB peak\n' "$1" "$2" "$3" \
        "$(memory_mb "${daemon}" VmRSS)" "$(memory_mb "${daemon}" VmHWM)"
}

# --- A server, and a folder of small files. ---

cat >"${WORK}/users.json" <<EOF
{"version":1,"users":[{"name":"bench","password":"${HOMEDRIVE_PASSWORD}","admin":true,"quota_gb":100}]}
EOF
export HD_DATA_DIR="${WORK}/store" HD_USERS_FILE="${WORK}/users.json"
export HD_LISTEN="127.0.0.1:${PORT}" HD_SECURE_COOKIES=false HD_MIN_FREE_GB=0
"${BIN}/hd-server" init >/dev/null
"${BIN}/hd-server" >"${WORK}/server.log" 2>&1 &
pids+=($!)
until curl -fs "http://127.0.0.1:${PORT}/healthz" >/dev/null; do sleep 0.2; done

"${BIN}/homedrive" login --server "http://127.0.0.1:${PORT}" --user bench --device bench >/dev/null
"${BIN}/homedrive" add-folder "${WORK}/local" >/dev/null

for ((i = 0; i < FILES; i++)); do
    dir="${WORK}/local/small/$((i % 50))/$((i % 7))"
    [[ -d "${dir}" ]] || mkdir -p "${dir}"
    printf 'file %d\n' "${i}" >"${dir}/${i}.txt"
done
echo "${FILES} files, binaries in ${BIN}"

# --- The first sync, then an idle daemon. ---

start_daemon --no-gui
started="$(date +%s)"
settle "${daemon}" 20
report "first sync, $(($(date +%s) - started - 20)) s" \
    "$(seconds "$(ticks "${daemon}")")" "$(wakeups "${daemon}")"
stop_daemon

start_daemon --no-gui
settle "${daemon}" 5
report "restarted, and scanned once" "$(seconds "$(ticks "${daemon}")")" "$(wakeups "${daemon}")"

cpu="$(ticks "${daemon}")"
woke="$(wakeups "${daemon}")"
sleep "${IDLE}"
report "idle for ${IDLE} s" "$(seconds $(($(ticks "${daemon}") - cpu)))" \
    "$(($(wakeups "${daemon}") - woke))"

# --- One edit. ---

cpu="$(ticks "${daemon}")"
woke="$(wakeups "${daemon}")"
printf 'edited\n' >"${WORK}/local/small/0/0/0.txt"
sleep 3
settle "${daemon}" 5
report "one file edited" "$(seconds $(($(ticks "${daemon}") - cpu)))" \
    "$(($(wakeups "${daemon}") - woke))"
stop_daemon

# --- The GUI left open, refreshing every 5 seconds for a minute. ---

start_daemon
settle "${daemon}" 5
info="${XDG_CONFIG_HOME}/homedrive/gui.json"
gui_port="$(sed -E 's/.*"port":([0-9]+).*/\1/' "${info}")"
gui_key="$(sed -E 's/.*"key":"([^"]+)".*/\1/' "${info}")"
cookies="${WORK}/cookies"
curl -fsL -c "${cookies}" -b "${cookies}" -o /dev/null \
    "http://127.0.0.1:${gui_port}/open?key=${gui_key}"
cpu="$(ticks "${daemon}")"
woke="$(wakeups "${daemon}")"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
    curl -fs -b "${cookies}" -o /dev/null "http://127.0.0.1:${gui_port}/"
    sleep 5
done
report "GUI open for 60 s" "$(seconds $(($(ticks "${daemon}") - cpu)))" \
    "$(($(wakeups "${daemon}") - woke))"
stop_daemon

# --- Sizes where batches and large files take over, up and then down. ---

mkdir -p "${WORK}/local/medium"
for ((i = 0; i < 256; i++)); do
    head -c 262144 /dev/urandom >"${WORK}/local/medium/${i}.bin"
done
head -c 268435456 /dev/urandom >"${WORK}/local/large.bin"

start_daemon --no-gui
settle "${daemon}" 5
settle "${daemon}" 20
report "64 MiB in 256 KiB files, 256 MiB up" "$(seconds "$(ticks "${daemon}")")" \
    "$(wakeups "${daemon}")"
stop_daemon

export XDG_CONFIG_HOME="${WORK}/config2" XDG_STATE_HOME="${WORK}/state2"
mkdir -p "${WORK}/local2"
"${BIN}/homedrive" login --server "http://127.0.0.1:${PORT}" --user bench --device second >/dev/null
"${BIN}/homedrive" add-folder "${WORK}/local2" >/dev/null
start_daemon --no-gui
settle "${daemon}" 20
report "and all of it down" "$(seconds "$(ticks "${daemon}")")" "$(wakeups "${daemon}")"
stop_daemon
