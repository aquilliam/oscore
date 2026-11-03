package oscore

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
)

func newPair(t testing.TB, edit func(client, server *Config)) (client, server *Context) {
	t.Helper()
	cc := &Config{
		MasterSecret: unhex(t, vectorSecret),
		MasterSalt:   unhex(t, "9e7ca92223786340"),
		SenderID:     []byte{0x01},
		RecipientID:  []byte{0x02},
	}
	sc := *cc
	sc.SenderID, sc.RecipientID = cc.RecipientID, cc.SenderID
	if edit != nil {
		edit(cc, &sc)
	}
	var err error
	if client, err = NewContext(cc); err != nil {
		t.Fatal(err)
	}
	if server, err = NewContext(&sc); err != nil {
		t.Fatal(err)
	}
	return client, server
}

func get(path string, opts ...Option) *Message {
	return &Message{Code: GET, Options: append([]Option{{Number: URIPath, Value: []byte(path)}}, opts...)}
}

// exchange protects m at the client and verifies it at the server.
func exchange(t testing.TB, client, server *Context, m *Message) (*Message, *Exchange, *Exchange) {
	t.Helper()
	out, cx, err := client.ProtectRequest(m)
	if err != nil {
		t.Fatal(err)
	}
	in, sx, err := server.UnprotectRequest(out)
	if err != nil {
		t.Fatal(err)
	}
	return in, cx, sx
}

func optionValues(m *Message, n OptionNumber) []string {
	var vs []string
	for _, o := range m.Options {
		if o.Number == n {
			vs = append(vs, string(o.Value))
		}
	}
	return vs
}

func TestAlgorithms(t *testing.T) {
	for alg := range aeads {
		for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			t.Run(fmt.Sprintf("%v/%v", alg, hash), func(t *testing.T) {
				client, server := newPair(t, func(c, s *Config) {
					c.AEAD, s.AEAD = alg, alg
					c.Hash, s.Hash = hash, hash
					c.IDContext, s.IDContext = []byte("ctx"), []byte("ctx")
				})
				req := &Message{Code: POST, Options: []Option{{Number: URIPath, Value: []byte("a")}}, Payload: []byte("hello")}
				in, cx, sx := exchange(t, client, server, req)
				if in.Code != POST || !bytes.Equal(in.Payload, req.Payload) {
					t.Fatalf("decrypted request = %+v", in)
				}
				out, err := sx.ProtectResponse(&Message{Code: Content, Payload: []byte("world")})
				if err != nil {
					t.Fatal(err)
				}
				resp, err := cx.UnprotectResponse(out)
				if err != nil {
					t.Fatal(err)
				}
				if resp.Code != Content || string(resp.Payload) != "world" {
					t.Fatalf("decrypted response = %+v", resp)
				}
				if alg.String() == "" || client.AEAD() != alg {
					t.Error("bad algorithm accessors")
				}
			})
		}
	}
}

func TestMismatchedContexts(t *testing.T) {
	client, server := newPair(t, func(c, s *Config) { s.MasterSalt = nil })
	out, _, err := client.ProtectRequest(get("a"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = server.UnprotectRequest(out)
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
	r := ErrorResponse(err)
	if r.Code != BadRequest || string(r.Payload) != "Decryption failed" {
		t.Errorf("error response = %+v", r)
	}
	if v, ok := r.option(MaxAge); !ok || len(v) != 0 {
		t.Error("error response has no Max-Age 0")
	}
}

func TestReplay(t *testing.T) {
	client, server := newPair(t, nil)
	out, _, err := client.ProtectRequest(get("a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.UnprotectRequest(out); err != nil {
		t.Fatal(err)
	}
	_, _, err = server.UnprotectRequest(out)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("err = %v, want ErrReplay", err)
	}
	if r := ErrorResponse(err); r.Code != Unauthorized || string(r.Payload) != "Replay detected" {
		t.Errorf("error response = %+v", r)
	}
}

func TestReplayWindow(t *testing.T) {
	client, server := newPair(t, func(c, s *Config) { s.ReplayWindowSize = 4 })
	var reqs []*Message
	for range 8 {
		out, _, err := client.ProtectRequest(get("a"))
		if err != nil {
			t.Fatal(err)
		}
		reqs = append(reqs, out)
	}
	accept := func(i int, want error) {
		t.Helper()
		if _, _, err := server.UnprotectRequest(reqs[i]); !errors.Is(err, want) {
			t.Errorf("request %d: err = %v, want %v", i, err, want)
		}
	}
	accept(5, nil)
	accept(3, nil) // out of order, inside the window
	accept(2, nil)
	accept(1, ErrReplay) // too old
	accept(3, ErrReplay)
	accept(7, nil)
	accept(4, nil)
	accept(3, ErrReplay)
	accept(6, nil)
	accept(6, ErrReplay)

	saved := server.ReplayWindow()
	_, restored := newPair(t, func(c, s *Config) { s.ReplayWindowSize = 4; s.ReplayWindow = &saved })
	if _, _, err := restored.UnprotectRequest(reqs[6]); !errors.Is(err, ErrReplay) {
		t.Errorf("restored window accepted a replay: %v", err)
	}
}

func TestReplayWindowShift(t *testing.T) {
	c := &Context{windowSize: 64}
	for _, seq := range []uint64{0, 63, 64, 200, 137, 138} {
		if c.replayed(seq) {
			t.Fatalf("%d reported as replay", seq)
		}
		c.accept(seq)
	}
	for _, seq := range []uint64{0, 63, 64, 136, 137, 138, 200} {
		if !c.replayed(seq) {
			t.Errorf("%d not reported as replay", seq)
		}
	}
	if c.replayed(199) == true || c.replayed(201) == true {
		t.Error("fresh Partial IV reported as replay")
	}
}

func TestUnknownContext(t *testing.T) {
	client, _ := newPair(t, nil)
	_, other := newPair(t, func(c, s *Config) { s.RecipientID = []byte{0x05} })
	out, _, err := client.ProtectRequest(get("a"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = other.UnprotectRequest(out)
	if !errors.Is(err, ErrUnknownContext) {
		t.Fatalf("err = %v, want ErrUnknownContext", err)
	}
	if r := ErrorResponse(err); r.Code != Unauthorized || string(r.Payload) != "Security context not found" {
		t.Errorf("error response = %+v", r)
	}

	// A request with a 'kid context' needs a context with that ID Context.
	client, server := newPair(t, func(c, s *Config) { c.IDContext = []byte{1} })
	out, _, err = client.ProtectRequest(get("a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.UnprotectRequest(out); !errors.Is(err, ErrUnknownContext) {
		t.Errorf("err = %v, want ErrUnknownContext", err)
	}
}

func TestEmptyKIDContext(t *testing.T) {
	client, server := newPair(t, func(c, s *Config) { c.IDContext, s.IDContext = []byte{}, []byte{} })
	out, _, err := client.ProtectRequest(get("a"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := ParseRequestID(out)
	if err != nil {
		t.Fatal(err)
	}
	if id.KIDContext == nil || len(id.KIDContext) != 0 {
		t.Errorf("KIDContext = %#v, want empty", id.KIDContext)
	}
	if _, _, err := server.UnprotectRequest(out); err != nil {
		t.Fatal(err)
	}
	if server.IDContext() == nil || client.IDContext() == nil {
		t.Error("IDContext() = nil for an empty ID Context")
	}
}

func TestMalformedRequests(t *testing.T) {
	client, server := newPair(t, nil)
	good, _, err := client.ProtectRequest(get("a"))
	if err != nil {
		t.Fatal(err)
	}
	oscoreValue, _ := good.option(OSCORE)
	with := func(value []byte, payload []byte) *Message {
		m := &Message{Code: POST, Payload: payload}
		m.Options = []Option{{Number: OSCORE, Value: value}}
		return m
	}
	tests := []struct {
		name string
		m    *Message
		want error
	}{
		{"no OSCORE option", get("a"), ErrNotProtected},
		{"no payload", with(oscoreValue, nil), ErrMalformed},
		{"two OSCORE options", &Message{Options: []Option{{OSCORE, oscoreValue}, {OSCORE, oscoreValue}}, Payload: good.Payload}, ErrMalformed},
		{"empty value", with([]byte{}, good.Payload), ErrMalformed},
		{"flags all zero", with([]byte{0}, good.Payload), ErrMalformed},
		{"reserved bit", with([]byte{0x29, 0, 1}, good.Payload), ErrMalformed},
		{"Partial IV length 6", with([]byte{0x0e, 1, 2, 3, 4, 5, 6, 1}, good.Payload), ErrMalformed},
		{"Partial IV too short", with([]byte{0x03, 1}, good.Payload), ErrMalformed},
		{"Partial IV with leading zero", with([]byte{0x0a, 0, 1, 1}, good.Payload), ErrMalformed},
		{"no kid", with([]byte{0x01, 0}, good.Payload), ErrMalformed},
		{"no Partial IV", with([]byte{0x08, 1}, good.Payload), ErrMalformed},
		{"kid context too long", with([]byte{0x19, 0, 5, 1}, good.Payload), ErrMalformed},
		{"kid context without length", with([]byte{0x11, 0}, good.Payload), ErrMalformed},
		{"short ciphertext", with(oscoreValue, []byte{1, 2, 3}), ErrDecrypt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := server.UnprotectRequest(tt.m)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			r := ErrorResponse(err)
			if tt.want == ErrMalformed && (r == nil || r.Code != BadOption) {
				t.Errorf("error response = %+v, want 4.02", r)
			}
		})
	}
	if _, _, err := server.UnprotectRequest(good); err != nil {
		t.Fatalf("good request: %v", err)
	}
}

func TestMalformedPlaintext(t *testing.T) {
	client, server := newPair(t, nil)
	for _, plaintext := range [][]byte{
		{},                             // no code
		{0x01, 0xff},                   // payload marker without payload
		{0x01, 0xf0},                   // reserved option delta
		{0x01, 0xb5, 'a'},              // option longer than the plaintext
		{0x01, 0x91, 0x00, 0xff, 0x01}, // OSCORE option inside
	} {
		piv, err := client.nextPIV()
		if err != nil {
			t.Fatal(err)
		}
		opt := &optionValue{piv: piv, kid: client.senderID, hasKID: true}
		m := &Message{Code: POST, Options: []Option{{Number: OSCORE, Value: opt.encode()}}}
		m.Payload = client.sender.Seal(nil, client.nonce(client.senderID, piv), plaintext, client.aad(client.senderID, piv))
		if _, _, err := server.UnprotectRequest(m); !errors.Is(err, errMalformedOptions) {
			t.Errorf("plaintext %x: err = %v", plaintext, err)
		} else if r := ErrorResponse(err); r.Code != BadOption {
			t.Errorf("plaintext %x: error response %v", plaintext, r.Code)
		}
	}
}

func TestOptionClasses(t *testing.T) {
	client, server := newPair(t, nil)
	req := &Message{Code: PUT, Options: []Option{
		{URIHost, []byte("example.com")},
		{URIPort, []byte{0x16, 0x34}},
		{URIPath, []byte("a")},
		{URIPath, []byte("b")},
		{ContentFormat, []byte{60}},
		{IfMatch, []byte{1}},
		{HopLimit, []byte{16}},
		{Block1, []byte{0x0e}},
		{Echo, []byte("echo")},
		{RequestTag, []byte{7}},
		{2048, []byte("unknown")},
	}, Payload: []byte("data")}
	out, _, err := client.ProtectRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != POST {
		t.Errorf("outer code = %v, want 0.02", out.Code)
	}
	var outer []OptionNumber
	for _, o := range out.Options {
		outer = append(outer, o.Number)
	}
	if want := []OptionNumber{URIHost, URIPort, OSCORE, HopLimit}; !slices.Equal(outer, want) {
		t.Errorf("outer options = %v, want %v", outer, want)
	}
	// Outer Class E options added on the way are discarded.
	out.Options = append(out.Options, Option{ETag, []byte{9}}, Option{URIPath, []byte("evil")})
	in, _, err := server.UnprotectRequest(out)
	if err != nil {
		t.Fatal(err)
	}
	if in.Code != PUT || string(in.Payload) != "data" {
		t.Errorf("decrypted request = %+v", in)
	}
	if !slices.EqualFunc(in.Options, sortOptions(req.Options), func(a, b Option) bool {
		return a.Number == b.Number && bytes.Equal(a.Value, b.Value)
	}) {
		t.Errorf("decrypted options = %v, want %v", in.Options, sortOptions(req.Options))
	}
	if _, _, err := client.ProtectRequest(&Message{Code: GET, Options: []Option{{OSCORE, nil}}}); !errors.Is(err, ErrNestedOSCORE) {
		t.Errorf("nested OSCORE: err = %v", err)
	}
	if _, _, err := client.ProtectRequest(&Message{Code: GET, Options: []Option{{URIPath, make([]byte, maxOptionValueLength+1)}}}); err == nil {
		t.Error("option longer than CoAP allows was accepted")
	}
}

func TestProxyURI(t *testing.T) {
	client, server := newPair(t, nil)
	out, _, err := client.ProtectRequest(&Message{Code: GET, Options: []Option{
		{ProxyURI, []byte("coap://example.com:5684/resource/a%2Fb?q=1&r=%26")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := optionValues(out, ProxyURI); !slices.Equal(got, []string{"coap://example.com:5684"}) {
		t.Errorf("outer Proxy-Uri = %q", got)
	}
	in, _, err := server.UnprotectRequest(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := optionValues(in, URIPath); !slices.Equal(got, []string{"resource", "a/b"}) {
		t.Errorf("Uri-Path = %q", got)
	}
	if got := optionValues(in, URIQuery); !slices.Equal(got, []string{"q=1", "r=&"}) {
		t.Errorf("Uri-Query = %q", got)
	}
	for _, bad := range []string{"/relative", "coap://user@example.com/", "coap://example.com/#frag", "coap:opaque", "coap://example.com/%zz", "coap://example.com/?%zz", "coap://[::1"} {
		if _, _, err := client.ProtectRequest(&Message{Code: GET, Options: []Option{{ProxyURI, []byte(bad)}}}); !errors.Is(err, errProxyURI) {
			t.Errorf("Proxy-Uri %q: err = %v", bad, err)
		}
	}
	for uri, want := range map[string]int{"coap://h": 0, "coap://h/": 0, "coap://h/a/": 2, "coap://h?": 0} {
		_, opts, err := splitProxyURI(uri)
		if err != nil || len(opts) != want {
			t.Errorf("%s: %d options, %v", uri, len(opts), err)
		}
	}
}

func TestSingleResponse(t *testing.T) {
	client, server := newPair(t, nil)
	_, cx, sx := exchange(t, client, server, get("a"))
	out, err := sx.ProtectResponse(&Message{Code: Content})
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != Changed {
		t.Errorf("outer code = %v, want 2.04", out.Code)
	}
	if v, _ := out.option(OSCORE); len(v) != 0 {
		t.Errorf("OSCORE option = %x, want empty", v)
	}
	if _, err := sx.ProtectResponse(&Message{Code: Content}); !errors.Is(err, ErrExchangeDone) {
		t.Errorf("second response: err = %v", err)
	}
	if _, err := cx.UnprotectResponse(out); err != nil {
		t.Fatal(err)
	}
	if _, err := cx.UnprotectResponse(out); !errors.Is(err, ErrReplay) {
		t.Errorf("replayed response: err = %v", err)
	}
	if _, err := cx.ProtectResponse(&Message{}); err == nil {
		t.Error("ProtectResponse on a client exchange succeeded")
	}
	if _, err := sx.UnprotectResponse(out); err == nil {
		t.Error("UnprotectResponse on a server exchange succeeded")
	}
}

func TestResponseErrors(t *testing.T) {
	client, server := newPair(t, nil)
	_, cx, sx := exchange(t, client, server, get("a"))
	out, err := sx.ProtectResponse(&Message{Code: Content, Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	tamper := func(f func(m *Message)) *Message {
		m := &Message{Code: out.Code, Options: slices.Clone(out.Options), Payload: bytes.Clone(out.Payload)}
		f(m)
		return m
	}
	for name, tt := range map[string]struct {
		m    *Message
		want error
	}{
		"plain":       {&Message{Code: Content}, ErrNotProtected},
		"flipped bit": {tamper(func(m *Message) { m.Payload[0] ^= 1 }), ErrDecrypt},
		"kid context": {tamper(func(m *Message) { m.Options[0].Value = []byte{0x10, 0} }), ErrMalformed},
		"other kid":   {tamper(func(m *Message) { m.Options[0].Value = []byte{0x08, 0x07} }), ErrUnknownContext},
		"bad flags":   {tamper(func(m *Message) { m.Options[0].Value = []byte{0x80} }), ErrMalformed},
	} {
		if _, err := cx.UnprotectResponse(tt.m); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tt.want)
		}
	}
	// A response may carry the server's kid.
	if _, err := cx.UnprotectResponse(tamper(func(m *Message) { m.Options[0].Value = []byte{0x08, 0x02} })); err != nil {
		t.Errorf("response with the server's kid: %v", err)
	}
}

func TestObserve(t *testing.T) {
	client, server := newPair(t, nil)
	req := get("temp", Option{Observe, []byte{}})
	out, cx, err := client.ProtectRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != FETCH {
		t.Errorf("outer code = %v, want 0.05", out.Code)
	}
	if got := optionValues(out, Observe); !slices.Equal(got, []string{""}) {
		t.Errorf("outer Observe = %q", got)
	}
	in, sx, err := server.UnprotectRequest(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := in.option(Observe); !ok {
		t.Fatal("decrypted request has no Observe")
	}
	var notes []*Message
	for i := range 4 {
		n, err := sx.ProtectResponse(&Message{Code: Content, Options: []Option{{Observe, encodeUint(uint64(100 + i))}}, Payload: []byte{byte(i)}})
		if err != nil {
			t.Fatal(err)
		}
		if n.Code != Content {
			t.Errorf("notification %d: outer code = %v", i, n.Code)
		}
		if v, _ := n.option(OSCORE); (i == 0) != (len(v) == 0) {
			t.Errorf("notification %d: OSCORE option %x", i, v)
		}
		notes = append(notes, n)
	}
	recv := func(i int, want error) *Message {
		t.Helper()
		m, err := cx.UnprotectResponse(notes[i])
		if !errors.Is(err, want) {
			t.Fatalf("notification %d: err = %v, want %v", i, err, want)
		}
		return m
	}
	m := recv(0, nil)
	if v, _ := m.option(Observe); len(v) != 0 {
		t.Errorf("first notification Observe = %x", v)
	}
	recv(0, ErrReplay)
	m = recv(2, nil)
	if v, _ := m.option(Observe); decodeUint(v) != 1 {
		t.Errorf("notification Observe = %x, want its Partial IV", v)
	}
	recv(1, ErrReplay) // older than the freshest
	recv(2, ErrReplay)
	recv(3, nil)

	// A notification for a request without Observe is rejected.
	_, cx2, sx2 := exchange(t, client, server, get("a"))
	n, err := sx2.ProtectResponse(&Message{Code: Content, Options: []Option{{Observe, []byte{1}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cx2.UnprotectResponse(n); !errors.Is(err, errUnexpectedObserve) {
		t.Errorf("err = %v", err)
	}
}

func TestEchoRecovery(t *testing.T) {
	client, server := newPair(t, func(c, s *Config) { s.ReplayWindowLost = true; s.SenderSequence = 50 })
	first, cx, err := client.ProtectRequest(get("a"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = server.UnprotectRequest(first)
	if !errors.Is(err, ErrEchoRequired) {
		t.Fatalf("err = %v, want ErrEchoRequired", err)
	}
	resp := ErrorResponse(err)
	if v, _ := resp.option(OSCORE); len(v) < 2 || v[0]&flagPIVMask == 0 {
		t.Fatalf("challenge has no Partial IV: %x", v)
	}
	challenge, err := cx.UnprotectResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	echo, ok := challenge.option(Echo)
	if challenge.Code != Unauthorized || !ok || len(echo) != echoSize || len(challenge.Payload) != 0 {
		t.Fatalf("challenge = %+v", challenge)
	}

	// A request without the Echo value is challenged again.
	again, _, err := client.ProtectRequest(get("a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.UnprotectRequest(again); !errors.Is(err, ErrEchoRequired) {
		t.Fatalf("err = %v, want ErrEchoRequired", err)
	}

	retry, _, err := client.ProtectRequest(get("a", Option{Echo, echo}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.UnprotectRequest(retry); err != nil {
		t.Fatal(err)
	}
	for _, old := range []*Message{first, again, retry} {
		if _, _, err := server.UnprotectRequest(old); !errors.Is(err, ErrReplay) {
			t.Errorf("err = %v, want ErrReplay", err)
		}
	}
	exchange(t, client, server, get("a"))
}

func TestReserve(t *testing.T) {
	var stored []uint64
	fail := false
	client, _ := newPair(t, func(c, s *Config) {
		c.SenderSequence = 5
		c.ReserveStep = 10
		c.Reserve = func(next uint64) error {
			if fail {
				return errors.New("disk full")
			}
			stored = append(stored, next)
			return nil
		}
	})
	for range 21 {
		if _, _, err := client.ProtectRequest(get("a")); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(stored, []uint64{15, 25, 35}) {
		t.Errorf("reserved %v", stored)
	}
	if client.SenderSequence() != 26 {
		t.Errorf("SenderSequence = %d", client.SenderSequence())
	}
	for range 9 {
		if _, _, err := client.ProtectRequest(get("a")); err != nil {
			t.Fatal(err)
		}
	}
	fail = true
	if _, _, err := client.ProtectRequest(get("a")); err == nil {
		t.Fatal("ProtectRequest succeeded without reserving")
	}
	if client.SenderSequence() != 35 {
		t.Errorf("SenderSequence = %d after failed reservation", client.SenderSequence())
	}
}

func TestSequenceExhausted(t *testing.T) {
	client, _ := newPair(t, func(c, s *Config) { c.SenderSequence = maxSenderSequenceNumber })
	out, _, err := client.ProtectRequest(get("a"))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := out.option(OSCORE); !bytes.Equal(v[1:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("OSCORE option %x", v)
	}
	if _, _, err := client.ProtectRequest(get("a")); !errors.Is(err, ErrSequenceExhausted) {
		t.Errorf("err = %v", err)
	}
}

func TestNewContextErrors(t *testing.T) {
	for name, edit := range map[string]func(*Config){
		"no secret":       func(c *Config) { c.MasterSecret = nil },
		"same IDs":        func(c *Config) { c.RecipientID = c.SenderID },
		"long Sender ID":  func(c *Config) { c.SenderID = make([]byte, 8) },
		"long for CCM-64": func(c *Config) { c.AEAD = AESCCM64_64_128; c.SenderID = []byte{1, 2} },
		"long for GCM":    func(c *Config) { c.AEAD = A128GCM; c.RecipientID = make([]byte, 7) },
		"algorithm":       func(c *Config) { c.AEAD = 99 },
		"hash":            func(c *Config) { c.Hash = crypto.MD5 },
		"window size":     func(c *Config) { c.ReplayWindowSize = 65 },
		"negative window": func(c *Config) { c.ReplayWindowSize = -1 },
		"sequence":        func(c *Config) { c.SenderSequence = maxSenderSequenceNumber + 1 },
	} {
		cfg := &Config{MasterSecret: []byte{1}, SenderID: []byte{1}, RecipientID: []byte{2}}
		edit(cfg)
		if _, err := NewContext(cfg); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if Algorithm(99).String() != "Algorithm(99)" || Algorithm(99).NonceSize() != 0 {
		t.Error("unknown Algorithm")
	}
	if AESCCM16_64_128.NonceSize() != 13 {
		t.Error("NonceSize")
	}
}

func TestAccessors(t *testing.T) {
	client, _ := newPair(t, nil)
	if !bytes.Equal(client.SenderID(), []byte{1}) || !bytes.Equal(client.RecipientID(), []byte{2}) || client.IDContext() != nil {
		t.Error("ID accessors")
	}
	if Content.String() != "2.05" || GET.String() != "0.01" {
		t.Error("Code.String")
	}
}

func TestSignaling(t *testing.T) {
	client, server := newPair(t, nil)
	const ping, pong Code = 0xe2, 0xe3
	in, cx, sx := exchange(t, client, server, &Message{Code: ping, Options: []Option{{2, nil}, {Observe, []byte{0}}}})
	if in.Code != ping || len(in.Options) != 2 {
		t.Fatalf("decrypted signal = %+v", in)
	}
	out, err := sx.ProtectResponse(&Message{Code: pong})
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != Changed {
		t.Errorf("outer code %v", out.Code)
	}
	if m, err := cx.UnprotectResponse(out); err != nil || m.Code != pong {
		t.Fatalf("%v %v", m, err)
	}
}

func TestErrorResponse(t *testing.T) {
	if ErrorResponse(errors.New("other")) != nil {
		t.Error("response for an unrelated error")
	}
	if r := ErrorResponse(ErrNotProtected); r.Code != Unauthorized || len(r.Payload) != 0 {
		t.Errorf("ErrNotProtected response = %+v", r)
	}
	if (&echoError{}).Error() != ErrEchoRequired.Error() {
		t.Error("echoError text")
	}
}

func TestConcurrent(t *testing.T) {
	client, server := newPair(t, func(c, s *Config) { s.ReplayWindowSize = 64 })
	const n = 64
	reqs := make(chan *Message, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			out, _, err := client.ProtectRequest(get("a"))
			if err != nil {
				t.Error(err)
				return
			}
			reqs <- out
		})
	}
	wg.Wait()
	close(reqs)
	var accepted sync.WaitGroup
	for m := range reqs {
		for range 2 {
			accepted.Go(func() { server.UnprotectRequest(m) })
		}
	}
	accepted.Wait()
	if w := server.ReplayWindow(); w.Highest != n-1 || w.Received != ^uint64(0) {
		t.Errorf("window = %+v", w)
	}
}
