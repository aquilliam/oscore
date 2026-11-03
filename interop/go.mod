module github.com/aquilliam/oscore/interop

go 1.25.0

require (
	github.com/aquilliam/edhoc v0.2.1
	github.com/aquilliam/oscore v0.0.0
)

require (
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/aquilliam/oscore => ../
