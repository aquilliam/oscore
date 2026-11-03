package oscore

import (
	"bytes"
	"testing"
)

func FuzzOptionValue(f *testing.F) {
	for _, s := range []string{"", "0914", "091400", "19140837cbf3210017a2d3", "0100", "1900", "e0"} {
		f.Add(unhex(f, s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := parseOptionValue(b)
		if err != nil {
			return
		}
		if got := v.encode(); !bytes.Equal(got, b) {
			t.Fatalf("encode(parse(%x)) = %x", b, got)
		}
	})
}

func FuzzOptions(f *testing.F) {
	for _, s := range []string{"", "396c6f63616c686f737483747631", "b3747631ff01", "d10100", "e1000001", "ff"} {
		f.Add(unhex(f, s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		opts, payload, err := parseOptions(b)
		if err != nil {
			return
		}
		got, err := appendOptions(nil, opts)
		if err != nil {
			t.Fatal(err)
		}
		if payload != nil {
			got = append(append(got, payloadMarker), payload...)
		}
		if !bytes.Equal(got, b) {
			t.Fatalf("options %x re-encoded as %x", b, got)
		}
	})
}

// FuzzRequest feeds a server an OSCORE option and payload.
func FuzzRequest(f *testing.F) {
	client, _ := newPair(f, nil)
	out, _, err := client.ProtectRequest(get("a"))
	if err != nil {
		f.Fatal(err)
	}
	v, _ := out.option(OSCORE)
	f.Add(v, out.Payload)
	f.Fuzz(func(t *testing.T, value, payload []byte) {
		_, server := newPair(t, nil)
		m := &Message{Code: POST, Options: []Option{{Number: OSCORE, Value: value}}, Payload: payload}
		if _, err := ParseRequestID(m); err != nil {
			return
		}
		if _, _, err := server.UnprotectRequest(m); err != nil {
			ErrorResponse(err)
		}
	})
}

// FuzzPlaintext encrypts a plaintext with the client's keys and has the
// server decrypt it, then protects the decrypted message again.
func FuzzPlaintext(f *testing.F) {
	for _, s := range []string{"01b3747631", "02ff00", "0161066000", "01d1ee00", "45ff48656c6c6f"} {
		f.Add(unhex(f, s))
	}
	f.Fuzz(func(t *testing.T, plaintext []byte) {
		client, server := newPair(t, nil)
		piv, err := client.nextPIV()
		if err != nil {
			t.Fatal(err)
		}
		opt := &optionValue{piv: piv, kid: client.senderID, hasKID: true}
		m := &Message{Code: POST, Options: []Option{{Number: OSCORE, Value: opt.encode()}}}
		m.Payload = client.sender.Seal(nil, client.nonce(client.senderID, piv), plaintext, client.aad(client.senderID, piv))
		in, x, err := server.UnprotectRequest(m)
		if err != nil {
			return
		}
		x.ProtectResponse(in)
		client.ProtectRequest(in)
	})
}

// FuzzResponse feeds a client an OSCORE option and payload in response to
// an Observe registration.
func FuzzResponse(f *testing.F) {
	client, server := newPair(f, nil)
	_, _, sx := exchange(f, client, server, get("a", Option{Observe, nil}))
	for range 2 {
		out, err := sx.ProtectResponse(&Message{Code: Content, Options: []Option{{Observe, []byte{1}}}})
		if err != nil {
			f.Fatal(err)
		}
		v, _ := out.option(OSCORE)
		f.Add(v, out.Payload)
	}
	f.Fuzz(func(t *testing.T, value, payload []byte) {
		client, _ := newPair(t, nil)
		_, cx, err := client.ProtectRequest(get("a", Option{Observe, nil}))
		if err != nil {
			t.Fatal(err)
		}
		cx.UnprotectResponse(&Message{Code: Content, Options: []Option{{Number: OSCORE, Value: value}}, Payload: payload})
	})
}
