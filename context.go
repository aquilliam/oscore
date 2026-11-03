package oscore

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	_ "crypto/sha256" // HKDF SHA-256
	_ "crypto/sha512" // HKDF SHA-384 and SHA-512
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/aquilliam/oscore/internal/ccm"
)

// An Algorithm is a COSE AEAD algorithm identifier (RFC 9053).
type Algorithm int

// The AEAD algorithms supported for OSCORE. AESCCM16_64_128 is the default
// and mandatory to implement (RFC 8613, Section 5).
const (
	A128GCM          Algorithm = 1
	A192GCM          Algorithm = 2
	A256GCM          Algorithm = 3
	AESCCM16_64_128  Algorithm = 10
	AESCCM16_64_256  Algorithm = 11
	AESCCM64_64_128  Algorithm = 12
	AESCCM64_64_256  Algorithm = 13
	ChaCha20Poly1305 Algorithm = 24
	AESCCM16_128_128 Algorithm = 30
	AESCCM16_128_256 Algorithm = 31
	AESCCM64_128_128 Algorithm = 32
	AESCCM64_128_256 Algorithm = 33
)

type aead struct {
	name      string
	keySize   int
	nonceSize int
	tagSize   int
	ccm       bool
}

var aeads = map[Algorithm]aead{
	A128GCM:          {"A128GCM", 16, 12, 16, false},
	A192GCM:          {"A192GCM", 24, 12, 16, false},
	A256GCM:          {"A256GCM", 32, 12, 16, false},
	AESCCM16_64_128:  {"AES-CCM-16-64-128", 16, 13, 8, true},
	AESCCM16_64_256:  {"AES-CCM-16-64-256", 32, 13, 8, true},
	AESCCM64_64_128:  {"AES-CCM-64-64-128", 16, 7, 8, true},
	AESCCM64_64_256:  {"AES-CCM-64-64-256", 32, 7, 8, true},
	ChaCha20Poly1305: {"ChaCha20/Poly1305", 32, 12, 16, false},
	AESCCM16_128_128: {"AES-CCM-16-128-128", 16, 13, 16, true},
	AESCCM16_128_256: {"AES-CCM-16-128-256", 32, 13, 16, true},
	AESCCM64_128_128: {"AES-CCM-64-128-128", 16, 7, 16, true},
	AESCCM64_128_256: {"AES-CCM-64-128-256", 32, 7, 16, true},
}

func (a Algorithm) String() string {
	if p, ok := aeads[a]; ok {
		return p.name
	}
	return fmt.Sprintf("Algorithm(%d)", int(a))
}

// NonceSize returns the length of the AEAD nonce, or 0 if the algorithm is
// not supported. Sender and Recipient IDs can be at most NonceSize() - 6
// bytes long.
func (a Algorithm) NonceSize() int {
	return aeads[a].nonceSize
}

func (a Algorithm) newAEAD(key []byte) (cipher.AEAD, error) {
	p := aeads[a]
	if a == ChaCha20Poly1305 {
		return chacha20poly1305.New(key)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if p.ccm {
		return ccm.New(b, p.tagSize, p.nonceSize)
	}
	return cipher.NewGCM(b)
}

// Config holds the input parameters of a security context (RFC 8613,
// Section 3.2) and how the context keeps its state across restarts.
type Config struct {
	// MasterSecret is required. MasterSalt may be empty.
	MasterSecret []byte
	MasterSalt   []byte
	// IDContext is the ID Context, or nil for none. A client sends it as
	// 'kid context' in every request; a server with several contexts for
	// the same Recipient ID uses it to tell them apart.
	IDContext []byte
	// SenderID and RecipientID must differ and be at most NonceSize() - 6
	// bytes long. Either may be empty.
	SenderID    []byte
	RecipientID []byte
	// AEAD is the AEAD algorithm. The default is AESCCM16_64_128.
	AEAD Algorithm
	// Hash is the hash function used with HKDF: crypto.SHA256 (the
	// default), crypto.SHA384 or crypto.SHA512. EDHOC's application hash
	// algorithms -16, -43 and -44 are these three.
	Hash crypto.Hash

	// SenderSequence is the first Sender Sequence Number to use: 0 for a
	// new context, or the value last stored by Reserve after a restart.
	SenderSequence uint64
	// Reserve, if not nil, makes Sender Sequence Numbers survive a restart
	// (RFC 8613, Appendix B.1.1). Before the context uses a number n for the
	// first time without having reserved it, it calls Reserve(n +
	// ReserveStep). Reserve must store that value durably before it
	// returns; after a restart, pass the stored value as SenderSequence.
	// If Reserve fails, so does the operation that needed the number.
	Reserve func(next uint64) error
	// ReserveStep is how many Sender Sequence Numbers each call to Reserve
	// covers. The default is 1.
	ReserveStep uint64

	// ReplayWindowSize is the number of Partial IVs the replay window
	// tracks, from 1 to 64. The default is 32.
	ReplayWindowSize int
	// ReplayWindow restores a replay window saved with Context.ReplayWindow,
	// or is nil for a context that has not received requests yet.
	ReplayWindow *ReplayWindow
	// ReplayWindowLost, for a context restored without its replay window,
	// makes the server check the freshness of the first request with the
	// Echo option before accepting requests (RFC 8613, Appendix B.1.2).
	ReplayWindowLost bool
}

// A ReplayWindow is the state of a replay window (RFC 8613, Section 7.4):
// the highest Partial IV received and, in bit i of Received, whether
// Highest - i was received. A zero ReplayWindow has received nothing.
type ReplayWindow struct {
	Highest  uint64
	Received uint64
}

// A Context is an OSCORE security context: the Common Context, the Sender
// Context and the Recipient Context of one endpoint (RFC 8613, Section 3).
// A Context is safe for concurrent use.
type Context struct {
	alg         Algorithm
	idContext   []byte
	senderID    []byte
	recipientID []byte
	commonIV    []byte
	sender      cipher.AEAD
	recipient   cipher.AEAD
	windowSize  int

	mu       sync.Mutex
	ssn      uint64
	reserved uint64
	reserve  func(uint64) error
	step     uint64
	window   ReplayWindow
	lost     bool
	echo     []byte
}

// NewContext derives a security context from cfg (RFC 8613, Section 3.2.1).
func NewContext(cfg *Config) (*Context, error) {
	alg := cfg.AEAD
	if alg == 0 {
		alg = AESCCM16_64_128
	}
	p, ok := aeads[alg]
	if !ok {
		return nil, fmt.Errorf("oscore: unsupported AEAD algorithm %d", int(alg))
	}
	hash := cfg.Hash
	if hash == 0 {
		hash = crypto.SHA256
	}
	if hash != crypto.SHA256 && hash != crypto.SHA384 && hash != crypto.SHA512 {
		return nil, fmt.Errorf("oscore: unsupported HKDF hash %v", hash)
	}
	if len(cfg.MasterSecret) == 0 {
		return nil, errors.New("oscore: empty Master Secret")
	}
	if max := p.nonceSize - 6; len(cfg.SenderID) > max || len(cfg.RecipientID) > max {
		return nil, fmt.Errorf("oscore: Sender and Recipient IDs must be at most %d bytes for %v", max, alg)
	}
	if bytes.Equal(cfg.SenderID, cfg.RecipientID) {
		return nil, errors.New("oscore: Sender ID and Recipient ID are equal")
	}
	if cfg.SenderSequence > maxSenderSequenceNumber {
		return nil, errors.New("oscore: Sender Sequence Number out of range")
	}
	size := cfg.ReplayWindowSize
	if size == 0 {
		size = defaultReplayWindowSize
	}
	if size < 1 || size > 64 {
		return nil, errors.New("oscore: replay window size must be from 1 to 64")
	}
	derive := func(id []byte, typ string, length int) ([]byte, error) {
		return hkdf.Key(hash.New, cfg.MasterSecret, cfg.MasterSalt, string(kdfInfo(id, cfg.IDContext, alg, typ, length)), length)
	}
	newAEAD := func(id []byte) (cipher.AEAD, error) {
		key, err := derive(id, "Key", p.keySize)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		return alg.newAEAD(key)
	}
	sender, err := newAEAD(cfg.SenderID)
	if err != nil {
		return nil, err
	}
	recipient, err := newAEAD(cfg.RecipientID)
	if err != nil {
		return nil, err
	}
	commonIV, err := derive([]byte{}, "IV", p.nonceSize)
	if err != nil {
		return nil, err
	}
	c := &Context{
		alg:         alg,
		senderID:    bytes.Clone(cfg.SenderID),
		recipientID: bytes.Clone(cfg.RecipientID),
		commonIV:    commonIV,
		sender:      sender,
		recipient:   recipient,
		windowSize:  size,
		ssn:         cfg.SenderSequence,
		reserved:    cfg.SenderSequence,
		reserve:     cfg.Reserve,
		step:        max(cfg.ReserveStep, 1),
		lost:        cfg.ReplayWindowLost,
	}
	if cfg.IDContext != nil {
		c.idContext = bytes.Clone(cfg.IDContext)
	}
	if cfg.ReplayWindow != nil {
		c.window = *cfg.ReplayWindow
		c.window.Received &= windowMask(size)
	}
	return c, nil
}

const (
	defaultReplayWindowSize = 32
	maxSenderSequenceNumber = 1<<40 - 1
	maxPIVSize              = 5
	echoSize                = 8
)

func windowMask(size int) uint64 {
	if size == 64 {
		return ^uint64(0)
	}
	return 1<<size - 1
}

// kdfInfo returns the info structure of RFC 8613, Section 3.2.1.
func kdfInfo(id, idContext []byte, alg Algorithm, typ string, length int) []byte {
	b := []byte{0x85}
	b = appendCBORBytes(b, id)
	if idContext == nil {
		b = append(b, 0xf6)
	} else {
		b = appendCBORBytes(b, idContext)
	}
	b = appendCBORInt(b, int64(alg))
	b = appendCBORHead(b, 3, uint64(len(typ)))
	b = append(b, typ...)
	return appendCBORHead(b, 0, uint64(length))
}

// aad returns the AAD of RFC 8613, Section 5.4, with no Class I options.
func (c *Context) aad(kid, piv []byte) []byte {
	a := []byte{0x85, 0x01, 0x81}
	a = appendCBORInt(a, int64(c.alg))
	a = appendCBORBytes(a, kid)
	a = appendCBORBytes(a, piv)
	a = append(a, 0x40)
	b := append([]byte{0x83, 0x68}, "Encrypt0"...)
	b = append(b, 0x40)
	return appendCBORBytes(b, a)
}

// nonce returns the AEAD nonce for a Partial IV generated by the endpoint
// with Sender ID id (RFC 8613, Section 5.2).
func (c *Context) nonce(id, piv []byte) []byte {
	n := bytes.Clone(c.commonIV)
	n[0] ^= byte(len(id))
	idEnd := len(n) - maxPIVSize
	subtleXOR(n[idEnd-len(id):idEnd], id)
	subtleXOR(n[len(n)-len(piv):], piv)
	return n
}

func subtleXOR(dst, src []byte) {
	for i := range src {
		dst[i] ^= src[i]
	}
}

// nextPIV returns the next Sender Sequence Number as a Partial IV.
func (c *Context) nextPIV() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ssn > maxSenderSequenceNumber {
		return nil, ErrSequenceExhausted
	}
	if c.reserve != nil && c.ssn >= c.reserved {
		next := min(c.ssn+c.step, maxSenderSequenceNumber+1)
		if err := c.reserve(next); err != nil {
			return nil, fmt.Errorf("oscore: reserving Sender Sequence Numbers: %w", err)
		}
		c.reserved = next
	}
	piv := encodePIV(c.ssn)
	c.ssn++
	return piv, nil
}

func encodePIV(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	return encodeUint(v)
}

// SenderSequence returns the next Sender Sequence Number the context will
// use.
func (c *Context) SenderSequence() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ssn
}

// ReplayWindow returns the state of the replay window, to be stored with
// the context and passed back in Config.ReplayWindow. It must not be used
// to restore a context that has received requests since it was saved.
func (c *Context) ReplayWindow() ReplayWindow {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.window
}

// AEAD returns the AEAD algorithm of the context.
func (c *Context) AEAD() Algorithm { return c.alg }

// SenderID returns the Sender ID.
func (c *Context) SenderID() []byte { return bytes.Clone(c.senderID) }

// RecipientID returns the Recipient ID.
func (c *Context) RecipientID() []byte { return bytes.Clone(c.recipientID) }

// IDContext returns the ID Context, or nil if the context has none.
func (c *Context) IDContext() []byte {
	if c.idContext == nil {
		return nil
	}
	return bytes.Clone(c.idContext)
}

// replayed reports whether seq is a replay or too old for the window.
func (c *Context) replayed(seq uint64) bool {
	w := c.window
	if w.Received == 0 || seq > w.Highest {
		return false
	}
	d := w.Highest - seq
	return d >= uint64(c.windowSize) || w.Received&(1<<d) != 0
}

// accept marks seq as received. The caller has checked replayed.
func (c *Context) accept(seq uint64) {
	w := &c.window
	switch {
	case w.Received == 0:
		w.Highest, w.Received = seq, 1
	case seq > w.Highest:
		if d := seq - w.Highest; d >= 64 {
			w.Received = 1
		} else {
			w.Received = w.Received<<d | 1
		}
		w.Highest = seq
	default:
		w.Received |= 1 << (w.Highest - seq)
	}
	w.Received &= windowMask(c.windowSize)
}

// echoValue returns the Echo value the server expects after losing its
// replay window, choosing one if needed.
func (c *Context) echoValue() ([]byte, error) {
	if c.echo == nil {
		e := make([]byte, echoSize)
		if _, err := rand.Read(e); err != nil {
			return nil, err
		}
		c.echo = e
	}
	return c.echo, nil
}

func appendCBORHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n <= 0xff:
		return append(b, m|24, byte(n))
	case n <= 0xffff:
		return append(b, m|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		return append(b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(b, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func appendCBORInt(b []byte, v int64) []byte {
	if v < 0 {
		return appendCBORHead(b, 1, uint64(-1-v))
	}
	return appendCBORHead(b, 0, uint64(v))
}

func appendCBORBytes(b, v []byte) []byte {
	return append(appendCBORHead(b, 2, uint64(len(v))), v...)
}
