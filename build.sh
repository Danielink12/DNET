#!/usr/bin/env bash
# Compila dnet-server y dnet-client para todas las combinaciones de
# GOOS/GOARCH soportadas, dejando los binarios en dist/<programa>/.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

# GOOS GOARCH ext
TARGETS=(
  "windows amd64 .exe"
  "linux   amd64 "
  "linux   arm64 "
  "darwin  amd64 "
  "darwin  arm64 "
)

build() {
  local prog="$1" goos="$2" goarch="$3" ext="$4"
  local out="dist/${prog}/dnet-${prog}-${goos}-${goarch}${ext}"

  mkdir -p "dist/${prog}"
  echo "==> ${prog} ${goos}/${goarch}"
  ( cd "$prog" && GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -o "../${out}" . )
}

for prog in server client; do
  for t in "${TARGETS[@]}"; do
    read -r goos goarch ext <<< "$t"
    build "$prog" "$goos" "$goarch" "$ext"
  done
done

echo
echo "Binarios generados en dist/"
