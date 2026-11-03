package oscore

import (
	"fmt"
	"slices"
)

// A Code is the code of a CoAP message (RFC 7252, Section 3): a 3-bit class
// and a 5-bit detail.
type Code uint8

// CoAP codes used by this package and common in applications.
const (
	GET    Code = 0x01
	POST   Code = 0x02
	PUT    Code = 0x03
	DELETE Code = 0x04
	FETCH  Code = 0x05
	PATCH  Code = 0x06
	IPATCH Code = 0x07

	Created             Code = 0x41
	Deleted             Code = 0x42
	Valid               Code = 0x43
	Changed             Code = 0x44
	Content             Code = 0x45
	BadRequest          Code = 0x80
	Unauthorized        Code = 0x81
	BadOption           Code = 0x82
	Forbidden           Code = 0x83
	NotFound            Code = 0x84
	InternalServerError Code = 0xa0
	ServiceUnavailable  Code = 0xa3
)

const (
	maxOptionValueLength = 65535 + 269
	payloadMarker        = 0xff
)

func (c Code) String() string {
	return fmt.Sprintf("%d.%02d", c>>5, c&0x1f)
}

func (c Code) signaling() bool { return c>>5 == 7 }

func (c Code) request() bool { return c>>5 == 0 && c != 0 }

func (c Code) response() bool { return c>>5 >= 2 && c>>5 <= 5 }

// An OptionNumber identifies a CoAP option.
type OptionNumber uint16

// CoAP option numbers from the CoAP Option Numbers registry.
const (
	IfMatch       OptionNumber = 1
	URIHost       OptionNumber = 3
	ETag          OptionNumber = 4
	IfNoneMatch   OptionNumber = 5
	Observe       OptionNumber = 6
	URIPort       OptionNumber = 7
	LocationPath  OptionNumber = 8
	OSCORE        OptionNumber = 9
	URIPath       OptionNumber = 11
	ContentFormat OptionNumber = 12
	MaxAge        OptionNumber = 14
	URIQuery      OptionNumber = 15
	HopLimit      OptionNumber = 16
	Accept        OptionNumber = 17
	QBlock1       OptionNumber = 19
	LocationQuery OptionNumber = 20
	EDHOC         OptionNumber = 21
	Block2        OptionNumber = 23
	Block1        OptionNumber = 27
	Size2         OptionNumber = 28
	QBlock2       OptionNumber = 31
	ProxyURI      OptionNumber = 35
	ProxyScheme   OptionNumber = 39
	Size1         OptionNumber = 60
	Echo          OptionNumber = 252
	NoResponse    OptionNumber = 258
	RequestTag    OptionNumber = 292
)

// classU reports whether the option is only an Outer option (Class U, RFC
// 8613, Section 4.1). Every other option is written to the plaintext.
func classU(n OptionNumber) bool {
	switch n {
	case URIHost, URIPort, OSCORE, HopLimit, EDHOC, ProxyURI, ProxyScheme:
		return true
	}
	return false
}

// An Option is a CoAP option.
type Option struct {
	Number OptionNumber
	Value  []byte
}

// A Message is the part of a CoAP message that OSCORE works on: the code,
// the options and the payload. The header fields of the transport, such as
// the Token, Type and Message ID, are not protected and are carried over
// from the original message by the caller.
//
// Options may be in any order; options with the same number keep their
// relative order.
type Message struct {
	Code    Code
	Options []Option
	Payload []byte
}

// option returns the value of the first option with number n.
func (m *Message) option(n OptionNumber) ([]byte, bool) {
	for _, o := range m.Options {
		if o.Number == n {
			return o.Value, true
		}
	}
	return nil, false
}

func (m *Message) count(n OptionNumber) int {
	c := 0
	for _, o := range m.Options {
		if o.Number == n {
			c++
		}
	}
	return c
}

// sortOptions returns the options sorted by number, keeping the order of
// options with the same number.
func sortOptions(opts []Option) []Option {
	s := slices.Clone(opts)
	slices.SortStableFunc(s, func(a, b Option) int { return int(a.Number) - int(b.Number) })
	return s
}

// appendOptions encodes sorted options as in RFC 7252, Section 3.1.
func appendOptions(b []byte, opts []Option) ([]byte, error) {
	prev := 0
	for _, o := range opts {
		if len(o.Value) > maxOptionValueLength {
			return nil, fmt.Errorf("oscore: option %d is too long", o.Number)
		}
		delta, length := int(o.Number)-prev, len(o.Value)
		prev = int(o.Number)
		i := len(b)
		b = append(b, 0)
		dn, b2 := optionNibble(b, delta)
		ln, b3 := optionNibble(b2, length)
		b3[i] = dn<<4 | ln
		b = append(b3, o.Value...)
	}
	return b, nil
}

func optionNibble(b []byte, v int) (byte, []byte) {
	switch {
	case v < 13:
		return byte(v), b
	case v < 269:
		return 13, append(b, byte(v-13))
	default:
		v -= 269
		return 14, append(b, byte(v>>8), byte(v))
	}
}

var errMalformedOptions = fmt.Errorf("%w: bad CoAP options", ErrMalformed)

// parseOptions decodes options and the payload as in RFC 7252, Section 3.1.
// The values share memory with b.
func parseOptions(b []byte) ([]Option, []byte, error) {
	var opts []Option
	number := 0
	for len(b) > 0 {
		if b[0] == payloadMarker {
			if len(b) == 1 {
				return nil, nil, errMalformedOptions
			}
			return opts, b[1:], nil
		}
		dn, ln := int(b[0]>>4), int(b[0]&0xf)
		b = b[1:]
		var delta, length int
		var ok bool
		if delta, b, ok = readNibble(b, dn); !ok {
			return nil, nil, errMalformedOptions
		}
		if length, b, ok = readNibble(b, ln); !ok || length > len(b) {
			return nil, nil, errMalformedOptions
		}
		number += delta
		if number > 0xffff {
			return nil, nil, errMalformedOptions
		}
		opts = append(opts, Option{Number: OptionNumber(number), Value: b[:length:length]})
		b = b[length:]
	}
	return opts, nil, nil
}

func readNibble(b []byte, n int) (int, []byte, bool) {
	switch n {
	case 13:
		if len(b) < 1 {
			return 0, nil, false
		}
		return int(b[0]) + 13, b[1:], true
	case 14:
		if len(b) < 2 {
			return 0, nil, false
		}
		return int(b[0])<<8 | int(b[1]) + 269, b[2:], true
	case 15:
		return 0, nil, false
	}
	return n, b, true
}

// encodeUint returns the shortest encoding of a uint option value.
func encodeUint(v uint64) []byte {
	var b []byte
	for ; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return b
}

func decodeUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}
