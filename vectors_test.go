package oscore

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"testing"
)

// The test vectors of RFC 8613, Appendix C.

type vectorContext struct {
	name                  string
	salt, idContext       string
	senderID, recipientID string
	senderInfo            string
	recipientInfo         string
	ivInfo                string
	senderKey             string
	recipientKey          string
	commonIV              string
	senderNonce           string
	recipientNonce        string
}

const vectorSecret = "0102030405060708090a0b0c0d0e0f10"

var vectorContexts = []vectorContext{
	{
		name: "C.1.1", salt: "9e7ca92223786340", senderID: "", recipientID: "01",
		senderInfo: "8540f60a634b657910", recipientInfo: "854101f60a634b657910", ivInfo: "8540f60a6249560d",
		senderKey: "f0910ed7295e6ad4b54fc793154302ff", recipientKey: "ffb14e093c94c9cac9471648b4f98710",
		commonIV: "4622d4dd6d944168eefb54987c", senderNonce: "4622d4dd6d944168eefb54987c", recipientNonce: "4722d4dd6d944169eefb54987c",
	},
	{
		name: "C.1.2", salt: "9e7ca92223786340", senderID: "01", recipientID: "",
		senderInfo: "854101f60a634b657910", recipientInfo: "8540f60a634b657910", ivInfo: "8540f60a6249560d",
		senderKey: "ffb14e093c94c9cac9471648b4f98710", recipientKey: "f0910ed7295e6ad4b54fc793154302ff",
		commonIV: "4622d4dd6d944168eefb54987c", senderNonce: "4722d4dd6d944169eefb54987c", recipientNonce: "4622d4dd6d944168eefb54987c",
	},
	{
		name: "C.2.1", senderID: "00", recipientID: "01",
		senderInfo: "854100f60a634b657910", recipientInfo: "854101f60a634b657910", ivInfo: "8540f60a6249560d",
		senderKey: "321b26943253c7ffb6003b0b64d74041", recipientKey: "e57b5635815177cd679ab4bcec9d7dda",
		commonIV: "be35ae297d2dace910c52e99f9", senderNonce: "bf35ae297d2dace910c52e99f9", recipientNonce: "bf35ae297d2dace810c52e99f9",
	},
	{
		name: "C.2.2", senderID: "01", recipientID: "00",
		senderInfo: "854101f60a634b657910", recipientInfo: "854100f60a634b657910", ivInfo: "8540f60a6249560d",
		senderKey: "e57b5635815177cd679ab4bcec9d7dda", recipientKey: "321b26943253c7ffb6003b0b64d74041",
		commonIV: "be35ae297d2dace910c52e99f9", senderNonce: "bf35ae297d2dace810c52e99f9", recipientNonce: "bf35ae297d2dace910c52e99f9",
	},
	{
		name: "C.3.1", salt: "9e7ca92223786340", idContext: "37cbf3210017a2d3", senderID: "", recipientID: "01",
		senderInfo: "85404837cbf3210017a2d30a634b657910", recipientInfo: "8541014837cbf3210017a2d30a634b657910",
		ivInfo:    "85404837cbf3210017a2d30a6249560d",
		senderKey: "af2a1300a5e95788b356336eeecd2b92", recipientKey: "e39a0c7c77b43f03b4b39ab9a268699f",
		commonIV: "2ca58fb85ff1b81c0b7181b85e", senderNonce: "2ca58fb85ff1b81c0b7181b85e", recipientNonce: "2da58fb85ff1b81d0b7181b85e",
	},
	{
		name: "C.3.2", salt: "9e7ca92223786340", idContext: "37cbf3210017a2d3", senderID: "01", recipientID: "",
		senderInfo: "8541014837cbf3210017a2d30a634b657910", recipientInfo: "85404837cbf3210017a2d30a634b657910",
		ivInfo:    "85404837cbf3210017a2d30a6249560d",
		senderKey: "e39a0c7c77b43f03b4b39ab9a268699f", recipientKey: "af2a1300a5e95788b356336eeecd2b92",
		commonIV: "2ca58fb85ff1b81c0b7181b85e", senderNonce: "2da58fb85ff1b81d0b7181b85e", recipientNonce: "2ca58fb85ff1b81c0b7181b85e",
	},
}

func (v *vectorContext) config(t testing.TB) *Config {
	cfg := &Config{
		MasterSecret: unhex(t, vectorSecret),
		MasterSalt:   unhex(t, v.salt),
		SenderID:     unhex(t, v.senderID),
		RecipientID:  unhex(t, v.recipientID),
	}
	if v.idContext != "" {
		cfg.IDContext = unhex(t, v.idContext)
	}
	return cfg
}

func vector(t testing.TB, name string) *vectorContext {
	for i := range vectorContexts {
		if vectorContexts[i].name == name {
			return &vectorContexts[i]
		}
	}
	t.Fatalf("no vector %s", name)
	return nil
}

func TestKeyDerivationVectors(t *testing.T) {
	for _, v := range vectorContexts {
		t.Run(v.name, func(t *testing.T) {
			cfg := v.config(t)
			c, err := NewContext(cfg)
			if err != nil {
				t.Fatal(err)
			}
			check := func(what string, got []byte, want string) {
				t.Helper()
				if !bytes.Equal(got, unhex(t, want)) {
					t.Errorf("%s = %x, want %s", what, got, want)
				}
			}
			check("sender info", kdfInfo(cfg.SenderID, cfg.IDContext, AESCCM16_64_128, "Key", 16), v.senderInfo)
			check("recipient info", kdfInfo(cfg.RecipientID, cfg.IDContext, AESCCM16_64_128, "Key", 16), v.recipientInfo)
			check("IV info", kdfInfo([]byte{}, cfg.IDContext, AESCCM16_64_128, "IV", 13), v.ivInfo)
			key := func(info string) []byte {
				k, err := hkdf.Key(sha256.New, cfg.MasterSecret, cfg.MasterSalt, string(unhex(t, info)), 16)
				if err != nil {
					t.Fatal(err)
				}
				return k
			}
			check("Sender Key", key(v.senderInfo), v.senderKey)
			check("Recipient Key", key(v.recipientInfo), v.recipientKey)
			check("Common IV", c.commonIV, v.commonIV)
			check("sender nonce", c.nonce(cfg.SenderID, []byte{0}), v.senderNonce)
			check("recipient nonce", c.nonce(cfg.RecipientID, []byte{0}), v.recipientNonce)
		})
	}
}

func TestAADExample(t *testing.T) {
	c := &Context{alg: AESCCM16_64_128}
	got := c.aad([]byte{0x00}, []byte{0x25})
	if want := unhex(t, "8368456e63727970743040498501810a4100412540"); !bytes.Equal(got, want) {
		t.Errorf("AAD = %x, want %x", got, want)
	}
}

func TestRequestVectors(t *testing.T) {
	tests := []struct {
		name, context, unprotected, protected string
	}{
		{"C.4", "C.1.1", "44015d1f00003974396c6f63616c686f737483747631",
			"44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e"},
		{"C.5", "C.2.1", "440171c30000b932396c6f63616c686f737483747631",
			"440271c30000b932396c6f63616c686f737463091400ff4ed339a5a379b0b8bc731fffb0"},
		{"C.6", "C.3.1", "44012f8eef9bbf7a396c6f63616c686f737483747631",
			"44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf3210017a2d3ff72cd7273fd331ac45cffbe55c3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := vector(t, tt.context).config(t)
			cfg.SenderSequence = 20
			client, err := NewContext(cfg)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := parseUDP(unhex(t, tt.unprotected))
			if err != nil {
				t.Fatal(err)
			}
			out, _, err := client.ProtectRequest(&plain.Message)
			if err != nil {
				t.Fatal(err)
			}
			protected := *plain
			protected.Message = *out
			if got := protected.marshal(t); !bytes.Equal(got, unhex(t, tt.protected)) {
				t.Errorf("protected request = %x, want %s", got, tt.protected)
			}

			server, err := NewContext(serverConfig(t, tt.context))
			if err != nil {
				t.Fatal(err)
			}
			received, err := parseUDP(unhex(t, tt.protected))
			if err != nil {
				t.Fatal(err)
			}
			id, err := ParseRequestID(&received.Message)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(id.KID, cfg.SenderID) || !bytes.Equal(id.KIDContext, cfg.IDContext) {
				t.Errorf("request ID = %x, %x", id.KID, id.KIDContext)
			}
			got, _, err := server.UnprotectRequest(&received.Message)
			if err != nil {
				t.Fatal(err)
			}
			decrypted := *plain
			decrypted.Message = *got
			if b := decrypted.marshal(t); !bytes.Equal(b, unhex(t, tt.unprotected)) {
				t.Errorf("decrypted request = %x, want %s", b, tt.unprotected)
			}
		})
	}
}

// serverConfig returns the peer of a client vector context.
func serverConfig(t testing.TB, client string) *Config {
	name := client[:len(client)-1] + "2"
	return vector(t, name).config(t)
}

func TestResponseVectors(t *testing.T) {
	const (
		request     = "44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e"
		unprotected = "64455d1f00003974ff48656c6c6f20576f726c6421"
	)
	tests := []struct {
		name      string
		fresh     bool
		protected string
	}{
		{"C.7", false, "64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106"},
		{"C.8", true, "64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewContext(vector(t, "C.1.2").config(t))
			if err != nil {
				t.Fatal(err)
			}
			req, err := parseUDP(unhex(t, request))
			if err != nil {
				t.Fatal(err)
			}
			_, x, err := server.UnprotectRequest(&req.Message)
			if err != nil {
				t.Fatal(err)
			}
			x.fresh = tt.fresh
			plain, err := parseUDP(unhex(t, unprotected))
			if err != nil {
				t.Fatal(err)
			}
			out, err := x.ProtectResponse(&plain.Message)
			if err != nil {
				t.Fatal(err)
			}
			protected := *plain
			protected.Message = *out
			if got := protected.marshal(t); !bytes.Equal(got, unhex(t, tt.protected)) {
				t.Errorf("protected response = %x, want %s", got, tt.protected)
			}

			cfg := vector(t, "C.1.1").config(t)
			cfg.SenderSequence = 20
			client, err := NewContext(cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, cx, err := client.ProtectRequest(&Message{Code: GET, Options: []Option{
				{Number: URIHost, Value: []byte("localhost")}, {Number: URIPath, Value: []byte("tv1")}}})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := parseUDP(unhex(t, tt.protected))
			if err != nil {
				t.Fatal(err)
			}
			got, err := cx.UnprotectResponse(&resp.Message)
			if err != nil {
				t.Fatal(err)
			}
			decrypted := *plain
			decrypted.Message = *got
			if b := decrypted.marshal(t); !bytes.Equal(b, unhex(t, unprotected)) {
				t.Errorf("decrypted response = %x, want %s", b, unprotected)
			}
		})
	}
}
