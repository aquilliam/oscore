#!/bin/sh
# Builds the uoscore-uedhoc peer as interop/.build/uoscore/peer.
set -eu

REPO=https://github.com/eriptic/uoscore-uedhoc.git
COMMIT=4e96e1a09ea1759be18aee546ef728d67b2c48df # v3.2.0

here=$(cd "$(dirname "$0")" && pwd)
out="$here/../.build/uoscore"
src="$out/src"

if [ ! -d "$src/.git" ]; then
	mkdir -p "$src"
	git -C "$src" init -q
	git -C "$src" remote add origin "$REPO"
fi
git -C "$src" fetch -q --depth 1 origin "$COMMIT"
git -C "$src" checkout -q "$COMMIT"
git -C "$src" submodule update -q --init --depth 1 \
	externals/zcbor externals/tinycrypt externals/compact25519

ext="$src/externals"
# crypto_p256.c is only used with mbedTLS.
common=$(ls "$src"/src/common/*.c | grep -v /crypto_p256.c)
${CC:-cc} -std=c11 -O1 -w \
	-DZCBOR -DZCBOR_CANONICAL -DTINYCRYPT -DCOMPACT25519 \
	-I"$src/inc" -I"$ext/tinycrypt/lib/include" -I"$ext/zcbor/include" \
	-I"$ext/compact25519/src" -I"$ext/compact25519/src/c25519" \
	"$src"/src/oscore/*.c $common "$src"/src/cbor/*.c \
	"$ext"/tinycrypt/lib/source/*.c \
	"$ext"/compact25519/src/*.c "$ext"/compact25519/src/c25519/*.c \
	"$ext"/zcbor/src/zcbor_common.c "$ext"/zcbor/src/zcbor_decode.c "$ext"/zcbor/src/zcbor_encode.c \
	"$here/peer.c" -o "$out/peer"
echo "$out/peer"
