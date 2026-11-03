# Changelog

All notable changes to this project are listed here. Versions follow
[semantic versioning](https://semver.org/). Until v1.0.0, minor versions may
include breaking changes.

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
