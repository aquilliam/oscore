// Package ccm implements the CCM mode of authenticated encryption defined in
// NIST SP 800-38C and RFC 3610.
//
// The COSE AES-CCM algorithms (RFC 9053, Section 4.2) are CCM with a 13- or
// 7-byte nonce and an 8- or 16-byte tag.
package ccm

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const blockSize = 16

var errOpen = errors.New("ccm: message authentication failed")

type ccm struct {
	b         cipher.Block
	tagSize   int
	nonceSize int
}

// New returns a CCM AEAD for a 128-bit block cipher such as AES. tagSize must
// be an even number from 4 to 16 and nonceSize a number from 7 to 13.
func New(b cipher.Block, tagSize, nonceSize int) (cipher.AEAD, error) {
	if b.BlockSize() != blockSize {
		return nil, errors.New("ccm: block size must be 16 bytes")
	}
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, errors.New("ccm: invalid tag size")
	}
	if nonceSize < 7 || nonceSize > 13 {
		return nil, errors.New("ccm: invalid nonce size")
	}
	return &ccm{b: b, tagSize: tagSize, nonceSize: nonceSize}, nil
}

func (c *ccm) NonceSize() int { return c.nonceSize }
func (c *ccm) Overhead() int  { return c.tagSize }

// lengthSize is L in RFC 3610: the number of bytes used to encode the
// message length.
func (c *ccm) lengthSize() int { return 15 - c.nonceSize }

// tooLong reports whether a message of n bytes cannot be encoded in L bytes.
func (c *ccm) tooLong(n int) bool {
	l := c.lengthSize()
	return l < 8 && uint64(n)>>(8*l) != 0
}

// counter returns block A_0, the first counter block.
func (c *ccm) counter(nonce []byte) [blockSize]byte {
	var a [blockSize]byte
	a[0] = byte(c.lengthSize() - 1)
	copy(a[1:], nonce)
	return a
}

// tag computes the CBC-MAC of the formatted nonce, additional data and
// plaintext and encrypts it with S_0.
func (c *ccm) tag(out, nonce, plaintext, additionalData []byte) {
	var b0 [blockSize]byte
	b0[0] = byte((c.tagSize-2)/2<<3 | (c.lengthSize() - 1))
	if len(additionalData) > 0 {
		b0[0] |= 0x40
	}
	copy(b0[1:], nonce)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(plaintext)))
	copy(b0[1+c.nonceSize:], n[8-c.lengthSize():])

	m := mac{b: c.b}
	m.write(b0[:])
	if len(additionalData) > 0 {
		var h []byte
		switch a := uint64(len(additionalData)); {
		case a < 0xff00:
			h = binary.BigEndian.AppendUint16(nil, uint16(a))
		case a <= 0xffffffff:
			h = binary.BigEndian.AppendUint32([]byte{0xff, 0xfe}, uint32(a))
		default:
			h = binary.BigEndian.AppendUint64([]byte{0xff, 0xff}, a)
		}
		m.write(h)
		m.write(additionalData)
		m.pad()
	}
	m.write(plaintext)
	m.pad()

	a0 := c.counter(nonce)
	var s0 [blockSize]byte
	c.b.Encrypt(s0[:], a0[:])
	subtle.XORBytes(out, m.x[:c.tagSize], s0[:c.tagSize])
}

// crypt encrypts or decrypts src into dst with counter blocks A_1, A_2, ...
func (c *ccm) crypt(dst, src, nonce []byte) {
	a := c.counter(nonce)
	a[blockSize-1] = 1
	cipher.NewCTR(c.b, a[:]).XORKeyStream(dst, src)
}

func (c *ccm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.nonceSize {
		panic("ccm: incorrect nonce length given to CCM")
	}
	if c.tooLong(len(plaintext)) {
		panic("ccm: message too large for CCM")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+c.tagSize)
	var t [blockSize]byte
	c.tag(t[:c.tagSize], nonce, plaintext, additionalData)
	c.crypt(out[:len(plaintext)], plaintext, nonce)
	copy(out[len(plaintext):], t[:c.tagSize])
	return ret
}

func (c *ccm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		panic("ccm: incorrect nonce length given to CCM")
	}
	if len(ciphertext) < c.tagSize {
		return nil, errOpen
	}
	n := len(ciphertext) - c.tagSize
	if c.tooLong(n) {
		return nil, errOpen
	}
	var received [blockSize]byte
	copy(received[:], ciphertext[n:])

	ret, out := sliceForAppend(dst, n)
	c.crypt(out, ciphertext[:n], nonce)
	var t [blockSize]byte
	c.tag(t[:c.tagSize], nonce, out, additionalData)
	if subtle.ConstantTimeCompare(t[:c.tagSize], received[:c.tagSize]) != 1 {
		clear(out)
		return nil, errOpen
	}
	return ret, nil
}

// mac computes a CBC-MAC with a zero IV.
type mac struct {
	b cipher.Block
	x [blockSize]byte
	n int // bytes absorbed into the current block
}

func (m *mac) write(p []byte) {
	for len(p) > 0 {
		k := subtle.XORBytes(m.x[m.n:], m.x[m.n:], p)
		m.n += k
		p = p[k:]
		if m.n == blockSize {
			m.b.Encrypt(m.x[:], m.x[:])
			m.n = 0
		}
	}
}

// pad finishes the current block with zeros.
func (m *mac) pad() {
	if m.n > 0 {
		m.b.Encrypt(m.x[:], m.x[:])
		m.n = 0
	}
}

// sliceForAppend extends in by n bytes and returns the whole slice and the
// new bytes.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	return head, head[len(in):]
}
