#!/bin/sh
#
# mic_live.sh -- live end to end test of the session microphone source.
#
# Builds and runs regress/integ/mic_live, which loads a real PulseAudio
# module-pipe-source named "rdp_microphone", records from it with parecord
# while feeding a known PCM signature through rdp_mic_write, verifies the
# signature round-trips into the recording, then tears the source and FIFO
# down and verifies both are gone.
#
# Requirements: pactl and parecord in /usr/bin and a reachable Pulse server
# (PipeWire-Pulse is fine).  NOT part of `make regress`.
#
# Usage: regress/integ/mic_live.sh

set -u

# Resolve the repo root from this script's location.
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root" || exit 2

recfile="$root/tmp/mic_live_$$.raw"
rc=1

cleanup() {
	# Unload any rdp_microphone module the harness may have left if it
	# died mid-run, and remove any leftover FIFO and record file.
	for idx in $(pactl list short modules 2>/dev/null \
	    | awk '/module-pipe-source/ && /rdp_microphone/ {print $1}'); do
		echo "cleanup: unloading leftover module $idx"
		pactl unload-module "$idx" 2>/dev/null
	done
	# Kill any stray parecord on our source.
	pkill -f 'parecord.*rdp_microphone' 2>/dev/null
	rm -f "$root"/tmp/rdp-mic-*.fifo 2>/dev/null
	rm -f "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"/rdp-mic-*.fifo 2>/dev/null
	rm -f "$recfile" 2>/dev/null
}
trap cleanup EXIT INT TERM

mkdir -p "$root/tmp"

# 1. Build the harness.
echo "building mic_live harness"
make regress/integ/mic_live >/dev/null || { echo "build failed"; exit 2; }

# 2. Run it.
echo "running mic_live harness"
./regress/integ/mic_live "$recfile"
rc=$?

if [ "$rc" -eq 0 ]; then
	echo "RESULT: PASS"
else
	echo "RESULT: FAIL (rc=$rc)"
fi
exit "$rc"
