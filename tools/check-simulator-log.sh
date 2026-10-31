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

# Don't let skipped tests hide a missing tpm2_eventlog
grep -q '^--- PASS: TestSimulatedTPM' "${log}" || reject "no simulated-TPM test passed"
! grep -q '^[[:space:]]*--- SKIP:' "${log}" || reject "tests were skipped"
