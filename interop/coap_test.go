package interop

import (
	"crypto/rand"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/aquilliam/oscore"
)

// CoAP over UDP message types (RFC 7252, Section 3).
const (
	con = 0
	non = 1
	ack = 2
	rst = 3
)

// A datagram is a CoAP over UDP message.
type datagram struct {
	typ   byte
	mid   uint16
	token []byte
	oscore.Message
}

func (d *datagram) marshal() []byte {
	b := []byte{1<<6 | d.typ<<4 | byte(len(d.token)), byte(d.Code), byte(d.mid >> 8), byte(d.mid)}
	b = append(b, d.token...)
	opts := slices.Clone(d.Options)
	slices.SortStableFunc(opts, func(a, b oscore.Option) int { return int(a.Number) - int(b.Number) })
	prev := 0
	for _, o := range opts {
		delta, length := int(o.Number)-prev, len(o.Value)
		prev = int(o.Number)
		head := len(b)
		b = append(b, 0)
		var dn, ln byte
		dn, b = nibble(b, delta)
		ln, b = nibble(b, length)
		b[head] = dn<<4 | ln
		b = append(b, o.Value...)
	}
	if len(d.Payload) > 0 {
		b = append(b, 0xff)
		b = append(b, d.Payload...)
	}
	return b
}

func nibble(b []byte, v int) (byte, []byte) {
	switch {
	case v < 13:
		return byte(v), b
	case v < 269:
		return 13, append(b, byte(v-13))
	}
	v -= 269
	return 14, append(b, byte(v>>8), byte(v))
}

var errMalformed = errors.New("malformed CoAP message")

func parseDatagram(b []byte) (*datagram, error) {
	if len(b) < 4 || b[0]>>6 != 1 {
		return nil, errMalformed
	}
	tkl := int(b[0] & 0xf)
	if tkl > 8 || len(b) < 4+tkl {
		return nil, errMalformed
	}
	d := &datagram{typ: b[0] >> 4 & 3, mid: uint16(b[2])<<8 | uint16(b[3]), token: b[4 : 4+tkl]}
	d.Code = oscore.Code(b[1])
	b = b[4+tkl:]
	number := 0
	for len(b) > 0 {
		if b[0] == 0xff {
			if len(b) == 1 {
				return nil, errMalformed
			}
			d.Payload = b[1:]
			break
		}
		delta, length := int(b[0]>>4), int(b[0]&0xf)
		b = b[1:]
		var ok bool
		if delta, b, ok = extended(b, delta); !ok {
			return nil, errMalformed
		}
		if length, b, ok = extended(b, length); !ok || length > len(b) {
			return nil, errMalformed
		}
		number += delta
		d.Options = append(d.Options, oscore.Option{Number: oscore.OptionNumber(number), Value: b[:length]})
		b = b[length:]
	}
	return d, nil
}

func extended(b []byte, n int) (int, []byte, bool) {
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

func option(m *oscore.Message, n oscore.OptionNumber) ([]byte, bool) {
	for _, o := range m.Options {
		if o.Number == n {
			return o.Value, true
		}
	}
	return nil, false
}

// A client sends CoAP requests over UDP to one server and collects the
// responses for each token. Its socket is not connected, since a server may
// answer from another socket bound to the same address.
type client struct {
	conn *net.UDPConn
	addr *net.UDPAddr
	mu   sync.Mutex
	mid  uint16
	subs map[string]chan *datagram
}

func dial(addr string) (*client, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: raddr.IP})
	if err != nil {
		return nil, err
	}
	c := &client{conn: conn, addr: raddr, subs: make(map[string]chan *datagram)}
	go c.read()
	return c, nil
}

func (c *client) read() {
	buf := make([]byte, 2048)
	for {
		n, from, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		d, err := parseDatagram(slices.Clone(buf[:n]))
		if err != nil {
			continue
		}
		if d.typ == con {
			c.conn.WriteToUDP((&datagram{typ: ack, mid: d.mid}).marshal(), from)
		}
		if d.Code == 0 {
			continue
		}
		c.mu.Lock()
		ch := c.subs[string(d.token)]
		c.mu.Unlock()
		if ch != nil {
			select {
			case ch <- d:
			default:
			}
		}
	}
}

// send sends m as a confirmable request and returns the channel of its
// responses.
func (c *client) send(m *oscore.Message) (chan *datagram, error) {
	token := make([]byte, 4)
	rand.Read(token)
	ch := make(chan *datagram, 16)
	c.mu.Lock()
	c.mid++
	d := &datagram{typ: con, mid: c.mid, token: token, Message: *m}
	c.subs[string(token)] = ch
	c.mu.Unlock()
	_, err := c.conn.WriteToUDP(d.marshal(), c.addr)
	return ch, err
}

func receive(ch chan *datagram) (*datagram, error) {
	select {
	case d := <-ch:
		return d, nil
	case <-time.After(5 * time.Second):
		return nil, errors.New("timed out waiting for a response")
	}
}
