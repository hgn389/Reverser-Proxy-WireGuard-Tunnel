#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# -eq 1 && $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  printf 'Usage: scripts/release.sh vX.Y.Z\n' >&2
  exit 2
}
version=$1
export GOTOOLCHAIN=auto
umask 022
unformatted=$(gofmt -l cmd internal web)
[[ -z $unformatted ]] || {
  printf 'Run gofmt on:\n%s\n' "$unformatted" >&2
  exit 1
}
go mod verify
go vet ./...
go test ./...
mkdir -p dist
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$version" -o "dist/rpctl-linux-$arch" ./cmd/rpctl
done
(
  cd dist
  sha256sum rpctl-linux-amd64 rpctl-linux-arm64 > SHA256SUMS
)
printf 'Release assets ready in dist/ for %s\n' "$version"
