#!/bin/sh
#
# printer_live.sh -- live end to end test of session printer redirection.
#
# Installs rdp-cups-backend into the system cupsd backend directory, builds
# and runs regress/integ/printer_live (which creates a real CUPS queue, prints
# a file through lp, and verifies the mock worker received the spool), then
# cleans up the queue, socket, installed backend, and any leftover CUPS jobs.
#
# Requirements: a running cupsd, lpadmin/lp/lpstat in PATH or /usr/sbin, and
# passwordless sudo to install the backend (root owned, 0755) into the cupsd
# backend dir.  NOT part of `make regress`.
#
# Usage: regress/integ/printer_live.sh

set -u

# Resolve the repo root from this script's location.
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root" || exit 2

backend_dir=/usr/lib/cups/backend
backend_dst="$backend_dir/rdp"
installed=0
rc=1

cleanup() {
	# Remove any queue the harness may have left if it died mid-run.
	for q in $(lpstat -p 2>/dev/null | awk '/^printer rdp-/ {print $2}'); do
		echo "cleanup: removing leftover queue $q"
		sudo /usr/sbin/lpadmin -x "$q" 2>/dev/null \
			|| lpadmin -x "$q" 2>/dev/null
	done
	# Cancel any leftover jobs on rdp- queues.
	cancel -a -x 2>/dev/null || true
	if [ "$installed" -eq 1 ]; then
		echo "cleanup: removing $backend_dst"
		sudo rm -f "$backend_dst"
	fi
	rm -f "$tmpfile" 2>/dev/null
}
trap cleanup EXIT INT TERM

# 1. Build the backend and the harness.
echo "building rdp-cups-backend and the live harness"
make src/session/rdp-cups-backend regress/integ/printer_live >/dev/null || {
	echo "build failed"; exit 2; }

# 2. Install the backend (root owned, 0755) so cupsd will run it.
echo "installing backend into $backend_dst (needs sudo)"
sudo install -o root -g root -m 0755 \
	src/session/rdp-cups-backend "$backend_dst" || {
	echo "backend install failed"; exit 2; }
installed=1

# 3. Make a known file to print.
tmpfile="$root/tmp/printer_live_$$.txt"
mkdir -p "$root/tmp"
printf 'rdpserver printer redirection live test\nmarker-%s\n' "$$" >"$tmpfile"

# 4. Run the harness.  A system cupsd runs the print backend as the "lp"
# user, which cannot traverse a private $XDG_RUNTIME_DIR (mode 0700).  Unset
# it (and $TMPDIR) so the module places its socket under /tmp (mode 1777),
# which the lp backend can reach; the socket itself is created 0666.  In a
# real deployment the session's runtime dir must likewise be reachable by the
# CUPS backend user (or a per-user cupsd is used).
echo "running printer_live harness"
env -u XDG_RUNTIME_DIR -u TMPDIR ./regress/integ/printer_live "$tmpfile"
rc=$?

if [ "$rc" -eq 0 ]; then
	echo "RESULT: PASS"
else
	echo "RESULT: FAIL (rc=$rc)"
fi
exit "$rc"
