# Interop tests

These tests run OSCORE over CoAP over UDP on localhost between this package
and other implementations, with Go as client and as server. Each test is
skipped unless its peer is set up:

```sh
# aiocoap
uv venv && uv pip install --require-hashes -r aiocoap/requirements.txt
export AIOCOAP_PYTHON=$PWD/.venv/bin/python

# libcoap, built with OpenSSL
git clone https://github.com/obgm/libcoap.git
git -C libcoap checkout 7cf7465b784baded4de183290c547d582becfd28 # v4.3.5
cmake -S libcoap -B libcoap/build -DENABLE_DTLS=ON -DDTLS_BACKEND=openssl \
  -DENABLE_OSCORE=ON -DENABLE_EXAMPLES=ON -DENABLE_DOCS=OFF -DENABLE_TESTS=OFF
cmake --build libcoap/build
# on macOS, add -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) to the first cmake
export LIBCOAP_BIN=$PWD/libcoap/build

go test ./...
```

TestEDHOC, which sets up contexts with
[github.com/aquilliam/edhoc](https://github.com/aquilliam/edhoc) for every
EDHOC cipher suite, needs no setup. CI runs all of them on every push.
