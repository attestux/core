#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <simulator.log>" >&2
	exit 2
fi
log="$1"
reject() {
	echo "${log}: $1" >&2
	exit 1
}

# Don't let skipped tests hide a missing tpm2_eventlog.
grep -q '^--- PASS: TestSimulatedTPM' "${log}" || {
	case $? in
		1) reject "no simulated-TPM test passed" ;;
		*) reject "failed to inspect simulator log" ;;
	esac
}
if grep -q '^[[:space:]]*--- SKIP:' "${log}"; then
	reject "tests were skipped"
elif [[ $? != 1 ]]; then
	reject "failed to inspect simulator log"
fi
