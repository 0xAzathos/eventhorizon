#!/usr/bin/env bash
# Builds release archives for every platform into dist/.
# Usage: scripts/release.sh v0.1.0
set -euo pipefail

version="${1:?usage: scripts/release.sh VERSION}"
root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$root/dist"
ldflags="-s -w -X github.com/0xAzathos/eventhorizon/internal/version.Version=$version"
targets="linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

rm -rf "$dist"
mkdir -p "$dist"

for target in $targets; do
	os="${target%/*}"
	arch="${target#*/}"
	name="eventhorizon_${version}_${os}_${arch}"
	stage="$dist/$name"
	ext=""
	[ "$os" = windows ] && ext=".exe"
	mkdir -p "$stage"

	export CGO_ENABLED=0 GOOS="$os" GOARCH="$arch"
	[ "$arch" = arm ] && export GOARM=7
	(cd "$root" && go build -trimpath -ldflags "$ldflags" -o "$stage/eventhorizon$ext" .)
	(cd "$root/telescope" && go build -trimpath -ldflags "$ldflags" -o "$stage/telescope$ext" .)
	unset GOARM

	cp "$root/LICENSE" "$root/README.md" "$stage/"
	[ "$os" = linux ] && cp "$root/deploy/eventhorizon.service" "$stage/"

	if [ "$os" = windows ]; then
		(cd "$dist" && zip -qr "$name.zip" "$name")
	else
		tar -C "$dist" -czf "$dist/$name.tar.gz" "$name"
	fi
	rm -rf "$stage"
	echo "built $name"
done

(cd "$dist" && sha256sum eventhorizon_* > checksums.txt)
echo "done: $dist"
