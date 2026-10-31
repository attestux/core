#!/usr/bin/env bash
set -euo pipefail

if [[ "${#}" -lt 1 || "${#}" -gt 2 || -z "${1}" || ( "${2:-false}" != true && "${2:-false}" != false ) ]]; then
	echo "usage: ${0} <output.aar> [true|false]" >&2
	exit 2
fi
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
aar="${1}"
simulator="${2:-false}"
ndk_version="$(<ndk.version)"

: "${ANDROID_HOME:?ANDROID_HOME must point to the Android SDK}"
export ANDROID_NDK_HOME="${ANDROID_HOME}/ndk/${ndk_version}"
export PATH="${project_dir}/build/mobile-tools:${PATH}"
GOTOOLCHAIN="$(go env GOVERSION)"
export GOTOOLCHAIN
# Select simulator trust only through this script's argument.
export GOFLAGS=
cd "${project_dir}"
go build -o "${project_dir}/build/mobile-tools/" \
	golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind

mkdir -p "$(dirname "${aar}")"
bind_arguments=(
	"-target=android/arm,android/arm64"
	-androidapi=23
	-javapkg=dev.attestux.nativecore
	-trimpath
)
if "${simulator}"; then
	bind_arguments+=(-tags=attestux_simulator)
fi
gomobile bind "${bind_arguments[@]}" -o "${aar}" github.com/attestux/core/mobilebind
