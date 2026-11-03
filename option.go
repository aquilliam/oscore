package oscore

import (
	"bytes"
	"errors"
)

// OSCORE flag bits (RFC 8613, Section 6.1).
const (
	flagPIVMask = 0x07
	flagKID     = 0x08
	flagContext = 0x10
	flagsUnused = 0xe0
)

// optionValue is the decoded value of an OSCORE option.
type optionValue struct {
	piv        []byte
	kid        []byte
	kidContext []byte
	hasKID     bool
	hasContext bool
}

func (v *optionValue) encode() []byte {
	flags := byte(len(v.piv))
	if v.hasKID {
		flags |= flagKID
	}
	if v.hasContext {
		flags |= flagContext
	}
	if flags == 0 {
		return []byte{}
	}
	b := append([]byte{flags}, v.piv...)
	if v.hasContext {
		b = append(b, byte(len(v.kidContext)))
		b = append(b, v.kidContext...)
	}
	return append(b, v.kid...)
}

var errMalformedOption = errors.New("oscore: malformed OSCORE option")

// parseOptionValue decodes an OSCORE option value. The fields share memory
// with b.
func parseOptionValue(b []byte) (*optionValue, error) {
	v := &optionValue{}
	if len(b) == 0 {
		return v, nil
	}
	flags := b[0]
	b = b[1:]
	if flags&flagsUnused != 0 {
		return nil, errMalformedOption
	}
	n := int(flags & flagPIVMask)
	if n > maxPIVSize || n > len(b) {
		return nil, errMalformedOption
	}
	if n > 1 && b[0] == 0 {
		return nil, errMalformedOption
	}
	if n > 0 {
		v.piv = b[:n:n]
	}
	b = b[n:]
	if flags&flagContext != 0 {
		if len(b) < 1 || int(b[0]) > len(b)-1 {
			return nil, errMalformedOption
		}
		s := int(b[0])
		v.hasContext = true
		v.kidContext = b[1 : 1+s : 1+s]
		b = b[1+s:]
	}
	if flags&flagKID != 0 {
		v.hasKID = true
		v.kid = b
	} else if len(b) > 0 {
		return nil, errMalformedOption
	}
	if flags == 0 {
		// The value is empty when all flag bits are zero.
		return nil, errMalformedOption
	}
	return v, nil
}

// A RequestID holds the identifiers in an OSCORE request that select the
// security context to verify it with.
type RequestID struct {
	// KID is the Sender ID of the client: the Recipient ID of the context.
	KID []byte
	// KIDContext is the 'kid context', the ID Context of the context, or
	// nil if the request has none.
	KIDContext []byte
}

// ParseRequestID returns the identifiers in the OSCORE option of a request,
// for a server to look up the security context to pass the request to with
// Context.UnprotectRequest. The fields share memory with m. If no context
// matches, the server can send ErrorResponse(ErrUnknownContext).
func ParseRequestID(m *Message) (*RequestID, error) {
	v, err := requestOption(m)
	if err != nil {
		return nil, err
	}
	id := &RequestID{KID: v.kid}
	if v.hasContext {
		id.KIDContext = v.kidContext
		if id.KIDContext == nil {
			id.KIDContext = []byte{}
		}
	}
	return id, nil
}

// requestOption returns the decoded OSCORE option of a request.
func requestOption(m *Message) (*optionValue, error) {
	raw, err := oscoreOption(m)
	if err != nil {
		return nil, err
	}
	v, err := parseOptionValue(raw)
	if err != nil {
		return nil, err
	}
	if v.piv == nil || !v.hasKID {
		return nil, errMalformedOption
	}
	return v, nil
}

// oscoreOption returns the value of the single OSCORE option of m.
func oscoreOption(m *Message) ([]byte, error) {
	switch m.count(OSCORE) {
	case 0:
		return nil, ErrNotProtected
	case 1:
	default:
		return nil, errMalformedOption
	}
	if len(m.Payload) == 0 {
		return nil, errMalformedOption
	}
	v, _ := m.option(OSCORE)
	return v, nil
}

func (c *Context) matches(v *optionValue) bool {
	if !bytes.Equal(v.kid, c.recipientID) {
		return false
	}
	return !v.hasContext || (c.idContext != nil && bytes.Equal(v.kidContext, c.idContext))
}
