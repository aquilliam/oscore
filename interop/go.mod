module github.com/aquilliam/oscore/interop

go 1.26.0

require (
	github.com/aquilliam/edhoc v1.0.0
	github.com/aquilliam/oscore v0.0.0
)

require (
	github.com/pion/dtls/v3 v3.1.16 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace github.com/aquilliam/oscore => ../
