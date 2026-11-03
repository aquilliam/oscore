package oscore

import "errors"

var (
	// ErrNotProtected is returned for a message without an OSCORE option.
	ErrNotProtected = errors.New("oscore: message is not protected with OSCORE")
	// ErrMalformed is returned for a message whose OSCORE option or decrypted
	// plaintext cannot be decoded.
	ErrMalformed = errors.New("oscore: malformed OSCORE message")
	// ErrUnknownContext is returned when a request is not for the context
	// it is passed to. A server that finds no context for a request can
	// send ErrorResponse(ErrUnknownContext).
	ErrUnknownContext = errors.New("oscore: security context not found")
	// ErrReplay is returned for a request or response that was received
	// before.
	ErrReplay = errors.New("oscore: replay detected")
	// ErrDecrypt is returned when a message fails to decrypt.
	ErrDecrypt = errors.New("oscore: decryption failed")
	// ErrSequenceExhausted is returned when a context has used all its
	// Sender Sequence Numbers and a new context is needed.
	ErrSequenceExhausted = errors.New("oscore: Sender Sequence Numbers exhausted")
	// ErrNestedOSCORE is returned when the message to protect already has
	// an OSCORE option.
	ErrNestedOSCORE = errors.New("oscore: message already has an OSCORE option")
	// ErrTooLarge is returned when a message is too large for the AEAD
	// algorithm: more than 65535 bytes of plaintext for AES-CCM with a
	// 13-byte nonce.
	ErrTooLarge = errors.New("oscore: message too large for the AEAD algorithm")
	// ErrCode is returned when a request to protect does not have a request
	// code or a response does not have a response code, other than a
	// signaling code.
	ErrCode = errors.New("oscore: wrong kind of CoAP code")
	// ErrExchangeDone is returned when a response is protected for an
	// exchange that cannot have another one.
	ErrExchangeDone = errors.New("oscore: exchange already has its response")
)

// ErrEchoRequired is returned by Context.UnprotectRequest when the context's
// replay window was lost and the request has not been shown to be fresh
// (RFC 8613, Appendix B.1.2). The request must not be processed.
// ErrorResponse(err) is a protected 4.01 (Unauthorized) response with an
// Echo option, which asks the client to send the request again with that
// option.
var ErrEchoRequired = errors.New("oscore: request freshness must be verified with Echo")

// echoError is an ErrEchoRequired with the response to send.
type echoError struct {
	response *Message
}

func (e *echoError) Error() string        { return ErrEchoRequired.Error() }
func (e *echoError) Is(target error) bool { return target == ErrEchoRequired }

// ErrorResponse returns the response a server sends when UnprotectRequest or
// ParseRequestID fails with err (RFC 8613, Section 8.2), or nil if it should
// send none. The response is an unprotected error with an Outer Max-Age of 0
// and a diagnostic payload, except for ErrEchoRequired, whose response is
// protected. For ErrNotProtected it is 4.01 (Unauthorized), for a server
// whose resources all require OSCORE.
func ErrorResponse(err error) *Message {
	var echo *echoError
	if errors.As(err, &echo) {
		return echo.response
	}
	var code Code
	var diag string
	switch {
	case errors.Is(err, ErrMalformed):
		code, diag = BadOption, "Failed to decode COSE"
	case errors.Is(err, ErrUnknownContext):
		code, diag = Unauthorized, "Security context not found"
	case errors.Is(err, ErrReplay):
		code, diag = Unauthorized, "Replay detected"
	case errors.Is(err, ErrDecrypt):
		code, diag = BadRequest, "Decryption failed"
	case errors.Is(err, ErrNotProtected):
		code = Unauthorized
	default:
		return nil
	}
	m := &Message{Code: code, Options: []Option{{Number: MaxAge, Value: []byte{}}}}
	if diag != "" {
		m.Payload = []byte(diag)
	}
	return m
}
