package interop

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/aquilliam/edhoc"

	"github.com/aquilliam/oscore"
)

// TestEDHOC derives OSCORE contexts from EDHOC sessions (RFC 9528,
// Appendix A.1) with each cipher suite of github.com/aquilliam/edhoc, and
// exchanges a request and a response.
func TestEDHOC(t *testing.T) {
	hashes := map[int]crypto.Hash{-16: crypto.SHA256, -43: crypto.SHA384, -44: crypto.SHA512}
	for _, suite := range []edhoc.Suite{edhoc.Suite0, edhoc.Suite1, edhoc.Suite2, edhoc.Suite3, edhoc.Suite4, edhoc.Suite5, edhoc.Suite6, edhoc.Suite24} {
		t.Run(suite.String(), func(t *testing.T) {
			initiator, responder := handshake(t, suite)
			var ctxs []*oscore.Context
			for _, s := range []*edhoc.Session{initiator, responder} {
				p, err := s.OSCORE()
				if err != nil {
					t.Fatal(err)
				}
				hash, ok := hashes[p.HashAlg]
				if !ok {
					t.Fatalf("hash %d", p.HashAlg)
				}
				ctx, err := oscore.NewContext(&oscore.Config{
					MasterSecret: p.MasterSecret,
					MasterSalt:   p.MasterSalt,
					SenderID:     p.SenderID,
					RecipientID:  p.RecipientID,
					AEAD:         oscore.Algorithm(p.AEADAlg),
					Hash:         hash,
				})
				if err != nil {
					t.Fatal(err)
				}
				ctxs = append(ctxs, ctx)
			}
			client, server := ctxs[0], ctxs[1]
			req, cx, err := client.ProtectRequest(&oscore.Message{Code: oscore.GET, Options: path("hello")})
			if err != nil {
				t.Fatal(err)
			}
			in, sx, err := server.UnprotectRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := sx.ProtectResponse(&oscore.Message{Code: oscore.Content, Payload: in.Options[0].Value})
			if err != nil {
				t.Fatal(err)
			}
			m, err := cx.UnprotectResponse(resp)
			if err != nil {
				t.Fatal(err)
			}
			if string(m.Payload) != "hello" {
				t.Errorf("response payload %q", m.Payload)
			}
		})
	}
}

func handshake(t *testing.T, suite edhoc.Suite) (initiator, responder *edhoc.Session) {
	t.Helper()
	newKey := func(kid byte) (*ecdh.PrivateKey, edhoc.Credential) {
		curve := ecdh.P256()
		switch suite {
		case edhoc.Suite0, edhoc.Suite1, edhoc.Suite4, edhoc.Suite6:
			curve = ecdh.X25519()
		case edhoc.Suite24:
			curve = ecdh.P384()
		}
		key, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cred, err := edhoc.NewCCS("", []byte{kid}, key.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		return key, cred
	}
	keyI, credI := newKey(0x01)
	keyR, credR := newKey(0x02)
	known := map[edhoc.IDCred]edhoc.Credential{credI.ID: credI, credR.ID: credR}
	lookUp := func(_ context.Context, p *edhoc.PeerInfo) (edhoc.Credential, error) {
		c, ok := known[p.ID]
		if !ok {
			return edhoc.Credential{}, edhoc.ErrUnknownCredential
		}
		return c, nil
	}
	cfg := func(cred edhoc.Credential, key *ecdh.PrivateKey) *edhoc.Config {
		return &edhoc.Config{Method: edhoc.MethodStaticStatic, Suites: []edhoc.Suite{suite}, Credential: cred, Key: key, PeerCredential: lookUp}
	}
	i, err := edhoc.NewInitiator(cfg(credI, keyI), []byte{0x37})
	if err != nil {
		t.Fatal(err)
	}
	r, err := edhoc.NewResponder(cfg(credR, keyR))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	msg1, err := i.WriteMessage1()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadMessage1(ctx, msg1); err != nil {
		t.Fatal(err)
	}
	msg2, err := r.WriteMessage2([]byte{0x27})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.ReadMessage2(ctx, msg2); err != nil {
		t.Fatal(err)
	}
	msg3, err := i.WriteMessage3()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadMessage3(ctx, msg3); err != nil {
		t.Fatal(err)
	}
	if initiator, err = i.Session(); err != nil {
		t.Fatal(err)
	}
	if responder, err = r.Session(); err != nil {
		t.Fatal(err)
	}
	return initiator, responder
}
