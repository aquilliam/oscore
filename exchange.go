package oscore

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"sync"
)

var errUnexpectedObserve = errors.New("oscore: Observe option in a response to a request without one")

// An Exchange binds the responses to a request to that request (RFC 8613,
// Section 7.1). A client gets one from ProtectRequest and verifies the
// responses with UnprotectResponse; a server gets one from UnprotectRequest
// and protects its responses with ProtectResponse.
//
// An exchange accepts one response, or, for an Observe registration, any
// number of notifications. It is safe for concurrent use.
type Exchange struct {
	c       *Context
	server  bool
	kid     []byte
	piv     []byte
	nonce   []byte
	observe bool
	fresh   bool // the server must use its own Partial IV

	mu           sync.Mutex
	responses    int
	nonceUsed    bool
	notification uint64
	notified     bool
}

// ProtectRequest protects a CoAP request (RFC 8613, Section 8.1). It returns
// the OSCORE request to send, with the same Token as m, and the exchange to
// verify the response with.
//
// The options of m are protected as RFC 8613, Section 4.1 says: Uri-Host,
// Uri-Port, Proxy-Scheme, Hop-Limit and EDHOC are left outside, Proxy-Uri is
// split, Observe is both inside and outside, and every other option is
// encrypted. Outer Block options for a proxy, if any, are added to the
// OSCORE request afterwards.
func (c *Context) ProtectRequest(m *Message) (*Message, *Exchange, error) {
	piv, err := c.nextPIV()
	if err != nil {
		return nil, nil, err
	}
	x := &Exchange{
		c:     c,
		kid:   c.senderID,
		piv:   piv,
		nonce: c.nonce(c.senderID, piv),
	}
	if v, ok := m.option(Observe); ok && decodeUint(v) == 0 && !m.Code.signaling() {
		x.observe = true
	}
	opt := &optionValue{piv: piv, kid: c.senderID, hasKID: true}
	if c.idContext != nil {
		opt.kidContext, opt.hasContext = c.idContext, true
	}
	out, err := c.seal(m, true, x.nonce, c.sender, c.aad(x.kid, x.piv), opt)
	if err != nil {
		return nil, nil, err
	}
	return out, x, nil
}

// UnprotectRequest verifies and decrypts an OSCORE request (RFC 8613,
// Section 8.2). It returns the decrypted request and the exchange to
// protect the responses with. The context must be the one whose Recipient
// ID and ID Context match the request; see ParseRequestID.
//
// If it fails, the request must not be processed; ErrorResponse(err) is the
// response to send, if any.
func (c *Context) UnprotectRequest(m *Message) (*Message, *Exchange, error) {
	v, err := requestOption(m)
	if err != nil {
		return nil, nil, err
	}
	if !c.matches(v) {
		return nil, nil, ErrUnknownContext
	}
	seq := decodeUint(v.piv)
	c.mu.Lock()
	replayed := !c.lost && c.replayed(seq)
	c.mu.Unlock()
	if replayed {
		return nil, nil, ErrReplay
	}
	x := &Exchange{
		c:      c,
		server: true,
		kid:    bytes.Clone(v.kid),
		piv:    bytes.Clone(v.piv),
		nonce:  c.nonce(v.kid, v.piv),
	}
	inner, err := c.open(m, x.nonce, c.recipient, c.aad(x.kid, x.piv))
	if err != nil {
		return nil, nil, err
	}
	if v, ok := inner.option(Observe); ok && decodeUint(v) == 0 && !inner.Code.signaling() {
		x.observe = true
	}

	c.mu.Lock()
	if c.lost {
		echo, ok := inner.option(Echo)
		if ok && c.echo != nil && bytes.Equal(echo, c.echo) {
			c.lost, c.echo = false, nil
			c.window = ReplayWindow{Highest: seq, Received: windowMask(c.windowSize)}
			c.mu.Unlock()
			return inner, x, nil
		}
		want, err := c.echoValue()
		c.mu.Unlock()
		if err != nil {
			return nil, nil, err
		}
		x.fresh = true
		resp, err := x.ProtectResponse(&Message{
			Code:    Unauthorized,
			Options: []Option{{Number: Echo, Value: bytes.Clone(want)}},
		})
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, &ErrEchoRequired{response: resp}
	}
	defer c.mu.Unlock()
	if c.replayed(seq) {
		return nil, nil, ErrReplay
	}
	c.accept(seq)
	return inner, x, nil
}

// ProtectResponse protects a CoAP response to the request of a server's
// exchange (RFC 8613, Section 8.3). It returns the OSCORE response to send,
// with the same Token as the request.
//
// The first response reuses the request's nonce; later notifications to an
// Observe registration get a Partial IV of their own. A response with an
// Observe option is protected as a notification.
func (x *Exchange) ProtectResponse(m *Message) (*Message, error) {
	if !x.server {
		return nil, errors.New("oscore: ProtectResponse called on a client exchange")
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.responses > 0 && !x.observe {
		return nil, ErrExchangeDone
	}
	c := x.c
	nonce := x.nonce
	opt := &optionValue{}
	if x.fresh || x.responses > 0 {
		piv, err := c.nextPIV()
		if err != nil {
			return nil, err
		}
		nonce = c.nonce(c.senderID, piv)
		opt.piv = piv
	}
	out, err := c.seal(m, false, nonce, c.sender, c.aad(x.kid, x.piv), opt)
	if err != nil {
		return nil, err
	}
	x.responses++
	return out, nil
}

// UnprotectResponse verifies and decrypts an OSCORE response to the request
// of a client's exchange (RFC 8613, Section 8.4). It returns the decrypted
// response. If it fails, the response must be ignored.
//
// For an Observe registration, notifications are accepted only if their
// Partial IV is higher than that of every notification accepted before
// (RFC 8613, Section 7.4.1). The Observe option of a decrypted notification
// is set to the three least significant bytes of its Partial IV, so that it
// orders notifications as RFC 7641 expects.
func (x *Exchange) UnprotectResponse(m *Message) (*Message, error) {
	if x.server {
		return nil, errors.New("oscore: UnprotectResponse called on a server exchange")
	}
	c := x.c
	raw, err := oscoreOption(m)
	if err != nil {
		return nil, err
	}
	v, err := parseOptionValue(raw)
	if err != nil {
		return nil, err
	}
	if v.hasContext {
		return nil, errMalformedOption
	}
	if v.hasKID && !bytes.Equal(v.kid, c.recipientID) {
		return nil, ErrUnknownContext
	}
	nonce := x.nonce
	if v.piv != nil {
		nonce = c.nonce(c.recipientID, v.piv)
	}
	inner, err := c.open(m, nonce, c.recipient, c.aad(x.kid, x.piv))
	if err != nil {
		return nil, err
	}
	_, notification := inner.option(Observe)
	notification = notification && !inner.Code.signaling()

	x.mu.Lock()
	defer x.mu.Unlock()
	switch {
	case !x.observe && notification:
		return nil, errUnexpectedObserve
	case !x.observe && x.responses > 0:
		return nil, ErrReplay
	case v.piv == nil:
		if x.nonceUsed {
			return nil, ErrReplay
		}
		x.nonceUsed = true
	default:
		seq := decodeUint(v.piv)
		if x.observe {
			if x.notified && seq <= x.notification {
				return nil, ErrReplay
			}
			x.notification, x.notified = seq, true
		}
	}
	x.responses++
	if notification {
		value := []byte{}
		if v.piv != nil {
			value = encodeUint(decodeUint(v.piv) & 0xffffff)
		}
		for i := range inner.Options {
			if inner.Options[i].Number == Observe {
				inner.Options[i].Value = value
			}
		}
	}
	return inner, nil
}

// seal builds the OSCORE message for m.
func (c *Context) seal(m *Message, request bool, nonce []byte, aead cipher.AEAD, aad []byte, opt *optionValue) (*Message, error) {
	inner, outer, err := splitOptions(m, request)
	if err != nil {
		return nil, err
	}
	plaintext := []byte{byte(m.Code)}
	if plaintext, err = appendOptions(plaintext, inner); err != nil {
		return nil, err
	}
	if len(m.Payload) > 0 {
		plaintext = append(plaintext, payloadMarker)
		plaintext = append(plaintext, m.Payload...)
	}
	out := &Message{Code: outerCode(m, request)}
	out.Options = sortOptions(append(outer, Option{Number: OSCORE, Value: opt.encode()}))
	out.Payload = aead.Seal(nil, nonce, plaintext, aad)
	clear(plaintext)
	return out, nil
}

// open decrypts the OSCORE message m and returns the decrypted message: the
// Code, options and payload from the plaintext, with the Outer Class U
// options other than OSCORE.
func (c *Context) open(m *Message, nonce []byte, aead cipher.AEAD, aad []byte) (*Message, error) {
	plaintext, err := aead.Open(nil, nonce, m.Payload, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(plaintext) == 0 {
		return nil, errMalformedOptions
	}
	opts, payload, err := parseOptions(plaintext[1:])
	if err != nil {
		return nil, err
	}
	inner := &Message{Code: Code(plaintext[0]), Payload: payload}
	for _, o := range m.Options {
		if classU(o.Number) && o.Number != OSCORE {
			inner.Options = append(inner.Options, Option{Number: o.Number, Value: bytes.Clone(o.Value)})
		}
	}
	for _, o := range opts {
		if o.Number == OSCORE {
			return nil, errMalformedOptions
		}
	}
	inner.Options = sortOptions(append(inner.Options, opts...))
	return inner, nil
}

func outerCode(m *Message, request bool) Code {
	_, observe := m.option(Observe)
	observe = observe && !m.Code.signaling()
	switch {
	case request && observe:
		return FETCH
	case request:
		return POST
	case observe:
		return Content
	}
	return Changed
}

// splitOptions sorts the options of m into Inner and Outer options (RFC
// 8613, Section 4.1).
func splitOptions(m *Message, request bool) (inner, outer []Option, err error) {
	for _, o := range m.Options {
		switch {
		case o.Number == OSCORE:
			return nil, nil, ErrNestedOSCORE
		case m.Code.signaling():
			inner = append(inner, o)
		case o.Number == Observe:
			outer = append(outer, o)
			if request {
				inner = append(inner, o)
			} else {
				inner = append(inner, Option{Number: Observe, Value: []byte{}})
			}
		case o.Number == ProxyURI && request:
			proxy, rest, err := splitProxyURI(string(o.Value))
			if err != nil {
				return nil, nil, err
			}
			outer = append(outer, Option{Number: ProxyURI, Value: []byte(proxy)})
			inner = append(inner, rest...)
		case classU(o.Number):
			outer = append(outer, o)
		default:
			inner = append(inner, o)
		}
	}
	return sortOptions(inner), outer, nil
}
