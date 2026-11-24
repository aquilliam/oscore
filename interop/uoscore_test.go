package interop

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/aquilliam/oscore"
)

// uoscore-uedhoc implements OSCORE only with AES-CCM-16-64-128.
var uoscoreSetups = libcoapSetups

// A uoscorePeer is one endpoint run by uoscore-uedhoc. It protects and
// unprotects CoAP over UDP messages.
type uoscorePeer struct {
	in  io.Writer
	out *bufio.Reader
	mid uint16
}

func startUoscore(t *testing.T, s setup, sender, recipient []byte) *uoscorePeer {
	bin := os.Getenv("UOSCORE_PEER")
	if bin == "" {
		t.Skip("UOSCORE_PEER is not set")
	}
	args := []string{fmt.Sprintf("%x", masterSecret), fmt.Sprintf("%x", masterSalt), fmt.Sprintf("%x", sender), fmt.Sprintf("%x", recipient)}
	if s.idContext != nil {
		args = append(args, fmt.Sprintf("%x", s.idContext))
	}
	cmd := exec.Command(bin, args...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cmd.Wait() })
	return &uoscorePeer{in: in, out: bufio.NewReader(out)}
}

// do runs op on m, sent with token, and returns the resulting message or the
// error uoscore-uedhoc returned.
func (p *uoscorePeer) do(t *testing.T, op string, token []byte, m *oscore.Message) (*oscore.Message, error) {
	t.Helper()
	p.mid++
	d := &datagram{typ: non, mid: p.mid, token: token, Message: *m}
	if _, err := fmt.Fprintf(p.in, "%s %x\n", op, d.marshal()); err != nil {
		t.Fatal(err)
	}
	line, err := p.out.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "error") {
		return nil, fmt.Errorf("uoscore %s: %s", op, line)
	}
	b, err := hex.DecodeString(line)
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseDatagram(b)
	if err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	return &r.Message, nil
}

func (p *uoscorePeer) must(t *testing.T, op string, token []byte, m *oscore.Message) *oscore.Message {
	t.Helper()
	r, err := p.do(t, op, token, m)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func equal(t *testing.T, got, want *oscore.Message) {
	t.Helper()
	if got.Code != want.Code || string(got.Payload) != string(want.Payload) || len(got.Options) != len(want.Options) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i, o := range got.Options {
		w := want.Options[i]
		if o.Number != w.Number || len(o.Value)+len(w.Value) > 0 && !reflect.DeepEqual(o.Value, w.Value) {
			t.Fatalf("option %d: got %v, want %v", i, o, w)
		}
	}
}

var uoscoreRequests = map[string]*oscore.Message{
	"GET":   {Code: oscore.GET, Options: path("hello")},
	"POST":  {Code: oscore.POST, Options: path("echo"), Payload: []byte("ping")},
	"query": {Code: oscore.GET, Options: []oscore.Option{{Number: oscore.URIHost, Value: []byte("example.com")}, {Number: oscore.URIPath, Value: []byte("a")}, {Number: oscore.URIQuery, Value: []byte("q=1")}, {Number: oscore.Accept, Value: []byte{60}}}},
	"Block1 with Request-Tag": {Code: oscore.PUT, Options: path("data",
		oscore.Option{Number: oscore.Block1, Value: []byte{0x0e}}, oscore.Option{Number: oscore.Size1, Value: []byte{4, 0}},
		oscore.Option{Number: oscore.RequestTag, Value: []byte{1, 2}}), Payload: make([]byte, 512)},
	"Block2":      {Code: oscore.GET, Options: path("data", oscore.Option{Number: oscore.Block2, Value: []byte{0x16}})},
	"No-Response": {Code: oscore.POST, Options: path("data", oscore.Option{Number: oscore.NoResponse, Value: []byte{26}}), Payload: []byte("x")},
}

var uoscoreResponse = &oscore.Message{Code: oscore.Content, Options: []oscore.Option{
	{Number: oscore.ETag, Value: []byte{1, 2, 3, 4}},
	{Number: oscore.MaxAge, Value: []byte{30}},
	{Number: oscore.Block2, Value: []byte{0x1e}},
}, Payload: []byte("Hello World!")}

func TestGoClientUoscoreServer(t *testing.T) {
	for _, s := range uoscoreSetups {
		for name, req := range uoscoreRequests {
			t.Run(s.String()+"/"+name, func(t *testing.T) {
				peer := startUoscore(t, s, serverID, clientID)
				ctx, err := oscore.NewContext(s.config(clientID, serverID))
				if err != nil {
					t.Fatal(err)
				}
				for i := range 3 {
					token := []byte{byte(i), 1}
					out, x, err := ctx.ProtectRequest(req)
					if err != nil {
						t.Fatal(err)
					}
					equal(t, peer.must(t, "unprotect", token, out), req)
					if _, err := peer.do(t, "unprotect", token, out); err == nil {
						t.Fatal("uoscore accepted a replay")
					}
					got, err := x.UnprotectResponse(peer.must(t, "protect", token, uoscoreResponse))
					if err != nil {
						t.Fatal(err)
					}
					equal(t, got, uoscoreResponse)
				}
			})
		}
	}
}

func TestUoscoreClientGoServer(t *testing.T) {
	for _, s := range uoscoreSetups {
		for name, req := range uoscoreRequests {
			t.Run(s.String()+"/"+name, func(t *testing.T) {
				peer := startUoscore(t, s, clientID, serverID)
				ctx, err := oscore.NewContext(s.config(serverID, clientID))
				if err != nil {
					t.Fatal(err)
				}
				for i := range 3 {
					token := []byte{byte(i), 1}
					in := peer.must(t, "protect", token, req)
					got, x, err := ctx.UnprotectRequest(in)
					if err != nil {
						t.Fatal(err)
					}
					equal(t, got, req)
					if _, _, err := ctx.UnprotectRequest(in); err == nil {
						t.Fatal("replay accepted")
					}
					out, err := x.ProtectResponse(uoscoreResponse)
					if err != nil {
						t.Fatal(err)
					}
					equal(t, peer.must(t, "unprotect", token, out), uoscoreResponse)
				}
			})
		}
	}
}

// TestGoClientUoscoreObserve has a uoscore-uedhoc server notify. Its client
// takes only notifications with a Partial IV and a kid.
func TestGoClientUoscoreObserve(t *testing.T) {
	register := &oscore.Message{Code: oscore.GET, Options: []oscore.Option{{Number: oscore.Observe}, {Number: oscore.URIPath, Value: []byte("counter")}}}
	notification := func(i byte) *oscore.Message {
		return &oscore.Message{Code: oscore.Content, Options: []oscore.Option{{Number: oscore.Observe, Value: []byte{i}}}, Payload: []byte{'0' + i}}
	}
	want := func(i byte) *oscore.Message {
		m := notification(i)
		m.Options[0].Value = nil
		return m
	}
	token := []byte{1, 2}
	peer := startUoscore(t, uoscoreSetups[0], serverID, clientID)
	ctx, err := oscore.NewContext(uoscoreSetups[0].config(clientID, serverID))
	if err != nil {
		t.Fatal(err)
	}
	out, x, err := ctx.ProtectRequest(register)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, peer.must(t, "unprotect", token, out), register)
	for i := range byte(3) {
		got, err := x.UnprotectResponse(peer.must(t, "protect", token, notification(i+1)))
		if err != nil {
			t.Fatal(err)
		}
		equal(t, got, want(i+1))
	}
}
