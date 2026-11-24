# Changelog

All notable changes to this project are listed here. Versions follow
[semantic versioning](https://semver.org/). Until v1.0.0, minor versions may
include breaking changes.

## Unreleased

Breaking changes:

- Go 1.26 or later is required, and `golang.org/x/crypto` is updated to
  v0.59.0.
- `Context.ReplayWindow` also returns whether the window is known. It is not
  while `ReplayWindowLost` is set and no client has answered the challenge.
  Saving it then made the context accept old requests after the next restart;
  `NewContext` now rejects the window returned in that state unless
  `ReplayWindowLost` is set again.
- `NewContext` returns an error if `ReplayWindowLost` is set without
  `Reserve`. Challenges use Sender Sequence Numbers, and without `Reserve`
  every restart used the same ones again.
- `NewContext` returns an error if the ID Context and the longer of the Sender
  and Recipient IDs do not fit in an OSCORE option of 255 bytes. Longer OSCORE
  options are rejected with `ErrMalformed`.
- `NewContext` returns `ErrSequenceExhausted` for a `SenderSequence` stored
  after the last Sender Sequence Number.
- `ProtectResponse` returns `ErrObserve` for an Observe option in a response to
  a request that is not an Observe registration, and so does
  `UnprotectResponse` for such a response.

Fixes:

- A replay window restored with a larger `ReplayWindowSize` no longer accepts
  requests received before it was saved. A window saved by v0.1.0 must be
  restored with the size it was saved with.
- A notification received after its observation has ended is an `ErrReplay`.
- The host in an Outer Proxy-Uri keeps its percent-encoding.

Other changes:

- The documentation says what a restored context must set, and that a context
  must be created only once from the same parameters.

## v0.1.0 (2026-11-03)

First release: RFC 8613 except Appendix B.2 and Section 11.

- Security contexts with every AEAD algorithm of RFC 9053, HKDF with
  SHA-256, SHA-384 or SHA-512, and an optional ID Context.
- Protection and verification of requests and responses, with Inner and
  Outer options, Proxy-Uri, Observe and signaling messages.
- Replay windows of 1 to 64 entries and ordered Observe notifications.
- Sender Sequence Numbers stored ahead of use, saved replay windows, and
  freshness checks with Echo after a lost replay window (Appendix B.1).
- Error responses for requests that fail to verify.
- Tested against the vectors of RFC 8613, Appendix C, and against aiocoap
  and libcoap.
