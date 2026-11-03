# Interop tests

These tests run OSCORE over CoAP over UDP on localhost between this package
and other implementations, with Go as client and as server. Each test is
skipped unless its peer is set up:

```sh
# aiocoap
uv venv && uv pip install "aiocoap[oscore]==0.4.17"
export AIOCOAP_PYTHON=$PWD/.venv/bin/python

# libcoap, built with OpenSSL
git clone --depth 1 --branch v4.3.5 https://github.com/obgm/libcoap.git
cmake -S libcoap -B libcoap/build -DENABLE_DTLS=ON -DDTLS_BACKEND=openssl \
  -DENABLE_OSCORE=ON -DENABLE_EXAMPLES=ON -DENABLE_DOCS=OFF -DENABLE_TESTS=OFF
cmake --build libcoap/build
# on macOS, add -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) to the first cmake
export LIBCOAP_BIN=$PWD/libcoap/build

go test ./...
```

CI runs them on every push.
