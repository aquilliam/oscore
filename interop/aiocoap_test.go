// Package interop runs OSCORE exchanges between this package and other
// implementations over CoAP over UDP on localhost.
//
// Each implementation has a peer program that serves /hello, /echo and the
// observable /counter, or requests them as a client. A test is skipped unless
// its environment variable points at the peer:
//
//	AIOCOAP_PYTHON    a Python with aiocoap[oscore] installed, such as
//	                  .venv/bin/python after
//	                  uv venv && uv pip install "aiocoap[oscore]==0.4.17"
//	LIBCOAP_BIN       a directory with the coap-client and coap-server examples
//	                  of libcoap 4.3.5, built with OSCORE
package interop

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aquilliam/oscore"
)

var (
	masterSecret = unhex("0102030405060708090a0b0c0d0e0f10")
	masterSalt   = unhex("9e7ca92223786340")
	clientID     = []byte{0x01}
	serverID     = []byte{0x02}
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// A setup is the security context both sides derive.
type setup struct {
	alg       oscore.Algorithm
	idContext []byte
}

var setups = []setup{
	{alg: oscore.AESCCM16_64_128},
	{alg: oscore.AESCCM16_64_128, idContext: unhex("37cbf3210017a2d3")},
	{alg: oscore.AESCCM16_128_256},
	{alg: oscore.A128GCM},
	{alg: oscore.ChaCha20Poly1305},
}

func (s setup) String() string {
	if s.idContext != nil {
		return s.alg.String() + " with ID Context"
	}
	return s.alg.String()
}

func (s setup) config(sender, recipient []byte) *oscore.Config {
	return &oscore.Config{
		MasterSecret: masterSecret,
		MasterSalt:   masterSalt,
		IDContext:    s.idContext,
		SenderID:     sender,
		RecipientID:  recipient,
		AEAD:         s.alg,
	}
}

// aiocoapContext writes an aiocoap security context directory.
func (s setup) aiocoapContext(t *testing.T, sender, recipient []byte, sequence map[string]any) string {
	dir := t.TempDir()
	settings := map[string]any{
		"sender-id_hex":    hex.EncodeToString(sender),
		"recipient-id_hex": hex.EncodeToString(recipient),
		"secret_hex":       hex.EncodeToString(masterSecret),
		"salt_hex":         hex.EncodeToString(masterSalt),
		"algorithm":        s.alg.String(),
	}
	if s.idContext != nil {
		settings["id-context_hex"] = hex.EncodeToString(s.idContext)
	}
	writeJSON(t, filepath.Join(dir, "settings.json"), settings)
	if sequence != nil {
		writeJSON(t, filepath.Join(dir, "sequence.json"), sequence)
	}
	return dir
}

func writeJSON(t *testing.T, name string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func aiocoapPython(t *testing.T) string {
	p := os.Getenv("AIOCOAP_PYTHON")
	if p == "" {
		t.Skip("AIOCOAP_PYTHON is not set")
	}
	return p
}

func freePort(t *testing.T) int {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// startAiocoapServer runs the aiocoap peer as a server and returns its
// address.
func startAiocoapServer(t *testing.T, context string) string {
	port := freePort(t)
	cmd := exec.Command(aiocoapPython(t), "aiocoap/peer.py", "server", strconv.Itoa(port), context)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("aiocoap server did not start: %q %v", line, err)
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func request(t *testing.T, c *client, ctx *oscore.Context, m *oscore.Message) (*oscore.Message, *oscore.Exchange, chan *datagram) {
	t.Helper()
	out, x, err := ctx.ProtectRequest(m)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := c.send(out)
	if err != nil {
		t.Fatal(err)
	}
	return next(t, x, ch), x, ch
}

func next(t *testing.T, x *oscore.Exchange, ch chan *datagram) *oscore.Message {
	t.Helper()
	d, err := receive(ch)
	if err != nil {
		t.Fatal(err)
	}
	m, err := x.UnprotectResponse(&d.Message)
	if err != nil {
		t.Fatalf("response %v: %v", d.Code, err)
	}
	return m
}

func path(p string, opts ...oscore.Option) []oscore.Option {
	return append([]oscore.Option{{Number: oscore.URIPath, Value: []byte(p)}}, opts...)
}

func TestGoClientAiocoapServer(t *testing.T) {
	for _, s := range setups {
		t.Run(s.String(), func(t *testing.T) {
			addr := startAiocoapServer(t, s.aiocoapContext(t, serverID, clientID, nil))
			ctx, err := oscore.NewContext(s.config(clientID, serverID))
			if err != nil {
				t.Fatal(err)
			}
			c, err := dial(addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.conn.Close()

			m, _, _ := request(t, c, ctx, &oscore.Message{Code: oscore.GET, Options: path("hello")})
			if m.Code != oscore.Content || string(m.Payload) != "Hello World!" {
				t.Errorf("GET /hello: %v %q", m.Code, m.Payload)
			}
			m, _, _ = request(t, c, ctx, &oscore.Message{Code: oscore.POST, Options: path("echo"), Payload: []byte("ping")})
			if m.Code != oscore.Changed || string(m.Payload) != "ping" {
				t.Errorf("POST /echo: %v %q", m.Code, m.Payload)
			}

			m, x, ch := request(t, c, ctx, &oscore.Message{Code: oscore.GET, Options: path("counter", oscore.Option{Number: oscore.Observe})})
			last := -1
			for i := 0; ; i++ {
				if _, ok := option(m, oscore.Observe); !ok || m.Code != oscore.Content {
					t.Fatalf("notification %d: %v without Observe", i, m.Code)
				}
				n, err := strconv.Atoi(string(m.Payload))
				if err != nil || n <= last {
					t.Fatalf("notification %d: %q after %d", i, m.Payload, last)
				}
				last = n
				if i == 3 {
					break
				}
				m = next(t, x, ch)
			}
		})
	}
}

func TestGoClientEchoRecovery(t *testing.T) {
	s := setups[0]
	addr := startAiocoapServer(t, s.aiocoapContext(t, serverID, clientID, map[string]any{"next-to-send": 100, "received": "unknown"}))
	ctx, err := oscore.NewContext(s.config(clientID, serverID))
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.conn.Close()
	m, _, _ := request(t, c, ctx, &oscore.Message{Code: oscore.GET, Options: path("hello")})
	echo, ok := option(m, oscore.Echo)
	if m.Code != oscore.Unauthorized || !ok {
		t.Fatalf("first request: %v, Echo %x", m.Code, echo)
	}
	m, _, _ = request(t, c, ctx, &oscore.Message{Code: oscore.GET, Options: path("hello", oscore.Option{Number: oscore.Echo, Value: echo})})
	if m.Code != oscore.Content || string(m.Payload) != "Hello World!" {
		t.Errorf("request with Echo: %v %q", m.Code, m.Payload)
	}
}

func TestAiocoapClientGoServer(t *testing.T) {
	for _, s := range setups {
		t.Run(s.String(), func(t *testing.T) { runAiocoapClient(t, s.config(serverID, clientID), s) })
	}
	t.Run("Echo recovery", func(t *testing.T) {
		cfg := setups[0].config(serverID, clientID)
		cfg.ReplayWindowLost = true
		runAiocoapClient(t, cfg, setups[0])
	})
}

// runAiocoapClient runs the aiocoap peer as a client of a Go server.
func runAiocoapClient(t *testing.T, cfg *oscore.Config, s setup) {
	py := aiocoapPython(t)
	ctx, err := oscore.NewContext(cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go serve(conn, ctx)
	uri := "coap://" + conn.LocalAddr().String()
	cmd := exec.Command(py, "aiocoap/peer.py", "client", uri, s.aiocoapContext(t, clientID, serverID, nil))
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	want := []string{"2.05 Content Hello World!", "2.04 Changed ping", "2.05 Content 0", "2.05 Content 1", "2.05 Content 2", "2.05 Content 3"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("aiocoap client printed\n%s\nwant\n%s", out, strings.Join(want, "\n"))
	}
}

// serve answers OSCORE requests on conn with ctx until conn is closed.
func serve(conn *net.UDPConn, ctx *oscore.Context) {
	var mid uint16 = 0x8000
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		d, err := parseDatagram(bytes.Clone(buf[:n]))
		if err != nil || d.typ == ack || d.typ == rst || d.Code == 0 {
			continue
		}
		reply := func(typ byte, id uint16, m *oscore.Message) {
			conn.WriteToUDP((&datagram{typ: typ, mid: id, token: d.token, Message: *m}).marshal(), addr)
		}
		typ := byte(non)
		if d.typ == con {
			typ = ack
		}
		in, x, err := ctx.UnprotectRequest(&d.Message)
		if err != nil {
			if r := oscore.ErrorResponse(err); r != nil {
				reply(typ, d.mid, r)
			}
			continue
		}
		p, _ := option(in, oscore.URIPath)
		var resp *oscore.Message
		observe := false
		switch {
		case string(p) == "hello" && in.Code == oscore.GET:
			resp = &oscore.Message{Code: oscore.Content, Payload: []byte("Hello World!")}
		case string(p) == "echo" && in.Code == oscore.POST:
			resp = &oscore.Message{Code: oscore.Changed, Payload: in.Payload}
		case string(p) == "counter" && in.Code == oscore.GET:
			v, ok := option(in, oscore.Observe)
			observe = ok && len(v) == 0
			resp = &oscore.Message{Code: oscore.Content, Payload: []byte("0")}
			if observe {
				resp.Options = []oscore.Option{{Number: oscore.Observe, Value: []byte{}}}
			}
		default:
			resp = &oscore.Message{Code: oscore.NotFound}
		}
		out, err := x.ProtectResponse(resp)
		if err != nil {
			continue
		}
		reply(typ, d.mid, out)
		if observe {
			go func() {
				for i := 1; i <= 3; i++ {
					time.Sleep(50 * time.Millisecond)
					out, err := x.ProtectResponse(&oscore.Message{Code: oscore.Content,
						Options: []oscore.Option{{Number: oscore.Observe, Value: []byte{byte(i)}}},
						Payload: []byte(strconv.Itoa(i))})
					if err != nil {
						return
					}
					mid++
					reply(con, mid, out)
				}
			}()
		}
	}
}
