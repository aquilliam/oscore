package oscore

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// udpMessage is a CoAP over UDP message (RFC 7252, Section 3), for tests.
type udpMessage struct {
	header [2]byte // version, type and token length; message ID high byte
	mid    uint16
	token  []byte
	Message
}

func parseUDP(b []byte) (*udpMessage, error) {
	if len(b) < 4 || b[0]>>6 != 1 || int(b[0]&0xf) > 8 || len(b) < 4+int(b[0]&0xf) {
		return nil, errors.New("bad header")
	}
	tkl := int(b[0] & 0xf)
	m := &udpMessage{mid: uint16(b[2])<<8 | uint16(b[3]), token: b[4 : 4+tkl]}
	m.header[0] = b[0]
	m.Code = Code(b[1])
	opts, payload, err := parseOptions(b[4+tkl:])
	if err != nil {
		return nil, err
	}
	m.Options, m.Payload = opts, payload
	return m, nil
}

func (m *udpMessage) marshal(t testing.TB) []byte {
	t.Helper()
	b := []byte{m.header[0], byte(m.Code), byte(m.mid >> 8), byte(m.mid)}
	b = append(b, m.token...)
	b, err := appendOptions(b, sortOptions(m.Options))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Payload) > 0 {
		b = append(b, payloadMarker)
		b = append(b, m.Payload...)
	}
	return b
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
