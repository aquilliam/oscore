# Contributing

Issues and pull requests are welcome. For anything larger than a small fix,
open an issue first so the approach can be agreed before you write code.

- Run `go vet ./...`, `staticcheck ./...` and `go test -race ./...` before
  sending a change.
- Changes to message processing need a test, ideally one taken from RFC 8613,
  Appendix C, or from an interop run.
- Keep dependencies to the standard library and `golang.org/x/crypto`.

Sign off each commit (`git commit -s`) to certify the
[Developer Certificate of Origin](https://developercertificate.org/).
