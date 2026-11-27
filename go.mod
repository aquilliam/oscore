module github.com/aquilliam/oscore

go 1.26.0

require (
	github.com/pion/dtls/v4 v4.0.2
	golang.org/x/crypto v0.59.0
)

require golang.org/x/sys v0.50.0 // indirect

retract v0.1.0 // Restored contexts can accept replayed requests and reuse nonces.
