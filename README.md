# oscore

[![Go Reference](https://pkg.go.dev/badge/github.com/aquilliam/oscore.svg)](https://pkg.go.dev/github.com/aquilliam/oscore)
[![codecov](https://codecov.io/gh/aquilliam/oscore/graph/badge.svg)](https://codecov.io/gh/aquilliam/oscore)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/17090/badge)](https://www.bestpractices.dev/projects/17090)

A Go implementation of OSCORE ([RFC 8613](https://www.rfc-editor.org/rfc/rfc8613)),
Object Security for Constrained RESTful Environments: end-to-end protection
of CoAP requests and responses. The package protects and verifies messages;
sending them, over UDP, TCP or anything else, is left to the application.

## Status

RFC 8613 is implemented except Appendix B.2 and the HTTP mapping of
Section 11. Hop-Limit is an Outer option, as in
[draft-ietf-core-oscore-capable-proxies](https://datatracker.ietf.org/doc/draft-ietf-core-oscore-capable-proxies/).
All test vectors of RFC 8613, Appendix C are reproduced exactly, and requests,
responses, Observe and Echo recovery work in both roles with
[aiocoap](https://github.com/chrysn/aiocoap) 0.4.17 and
[libcoap](https://github.com/obgm/libcoap) 4.3.5. Requests and responses also
work in both roles with
[uoscore-uedhoc](https://github.com/eriptic/uoscore-uedhoc) 3.2.0, and Observe
with its server (see [interop](interop)).

Supported:

- Every AEAD algorithm of RFC 9053 (AES-CCM, AES-GCM, ChaCha20/Poly1305) and
  HKDF with SHA-256, SHA-384 or SHA-512
- ID Context and 'kid context'
- Inner and Outer options, including Proxy-Uri, Observe, Block-wise, Echo,
  Request-Tag, Hop-Limit and EDHOC
- Replay windows of 1 to 64 entries, and in-order Observe notifications
- Sender Sequence Numbers stored ahead of use (Appendix B.1.1), and
  freshness checks with Echo after a server loses its replay window
  (Appendix B.1.2)
- Error responses for failed verification (Section 8.2)
- Signaling messages over reliable transports (Section 4.3)

The code is pure Go with no cgo or `unsafe`, and depends only on the standard
library and `golang.org/x/crypto`.

## Example

See [example_test.go](example_test.go) for a server with several clients,
Observe, and a context kept across reboots. In short, with some error
handling left out:

```go
// Client
client, err := oscore.NewContext(&oscore.Config{
	MasterSecret: secret,
	MasterSalt:   salt,
	SenderID:     []byte{0x01},
	RecipientID:  []byte{0x02},
})
protected, exchange, err := client.ProtectRequest(&oscore.Message{
	Code:    oscore.GET,
	Options: []oscore.Option{{Number: oscore.URIPath, Value: []byte("temperature")}},
})
// send protected with a new Token, receive the response with that Token
resp, err := exchange.UnprotectResponse(protectedResp)

// Server
id, err := oscore.ParseRequestID(protected)
if err != nil {
	// if err is oscore.ErrNotProtected and the resource does not require
	// OSCORE, handle the request; otherwise send oscore.ErrorResponse(err)
	return
}
server, ok := contexts[string(id.KID)]
if !ok {
	// send oscore.ErrorResponse(oscore.ErrUnknownContext)
	return
}
req, exchange, err := server.UnprotectRequest(protected)
if err != nil {
	// send oscore.ErrorResponse(err), if not nil
	return
}
protectedResp, err := exchange.ProtectResponse(&oscore.Message{Code: oscore.Content, Payload: data})
```

A context set up with [EDHOC](https://github.com/aquilliam/edhoc) takes its
`Config` from `Session.OSCORE()`: `MasterSecret`, `MasterSalt`, `SenderID` and
`RecipientID` as they are, `AEAD` as `oscore.Algorithm(p.AEADAlg)`, and
`Hash` as `crypto.SHA256`, `crypto.SHA384` or `crypto.SHA512` for `HashAlg`
-16, -43 or -44.

## Go versions

Go 1.26 or later. CI tests 1.26 and the latest release.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Copyright 2026 Last Lock Inc. Apache License 2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE).
