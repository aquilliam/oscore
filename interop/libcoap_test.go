package interop

import (
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

// libcoap 4.3.5 with OpenSSL protects OSCORE messages only with
// AES-CCM-16-64-128.
var libcoapSetups = []setup{
	{alg: oscore.AESCCM16_64_128},
	{alg: oscore.AESCCM16_64_128, idContext: unhex("37cbf3210017a2d3")},
}

func libcoapBin(t *testing.T, name string) string {
	dir := os.Getenv("LIBCOAP_BIN")
	if dir == "" {
		t.Skip("LIBCOAP_BIN is not set")
	}
	return filepath.Join(dir, name)
}

// libcoapConfig writes a libcoap OSCORE configuration file.
func (s setup) libcoapConfig(t *testing.T, sender, recipient []byte) string {
	lines := []string{
		fmt.Sprintf("master_secret,hex,%x", masterSecret),
		fmt.Sprintf("master_salt,hex,%x", masterSalt),
		fmt.Sprintf("sender_id,hex,%x", sender),
		fmt.Sprintf("recipient_id,hex,%x", recipient),
		fmt.Sprintf("aead_alg,integer,%d", s.alg),
	}
	if s.idContext != nil {
		lines = append(lines, fmt.Sprintf("id_context,hex,%x", s.idContext))
	}
	name := filepath.Join(t.TempDir(), "oscore.conf")
	if err := os.WriteFile(name, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestGoClientLibcoapServer(t *testing.T) {
	for _, s := range libcoapSetups {
		t.Run(s.String(), func(t *testing.T) {
			port := freePort(t)
			cmd := exec.Command(libcoapBin(t, "coap-server"), "-E", s.libcoapConfig(t, serverID, clientID), "-A", "127.0.0.1", "-p", strconv.Itoa(port))
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
			ctx, err := oscore.NewContext(s.config(clientID, serverID))
			if err != nil {
				t.Fatal(err)
			}
			c, err := dial(fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				t.Fatal(err)
			}
			defer c.conn.Close()
			waitForServer(t, c, ctx)

			m, _, _ := request(t, c, ctx, &oscore.Message{Code: oscore.PUT, Options: path("example_data"), Payload: []byte("hi")})
			if m.Code != oscore.Changed && m.Code != oscore.Created {
				t.Errorf("PUT /example_data: %v %q", m.Code, m.Payload)
			}
			m, _, _ = request(t, c, ctx, &oscore.Message{Code: oscore.GET, Options: path("example_data")})
			if m.Code != oscore.Content || string(m.Payload) != "hi" {
				t.Errorf("GET /example_data: %v %q", m.Code, m.Payload)
			}
			m, x, ch := request(t, c, ctx, &oscore.Message{Code: oscore.GET, Options: path("time", oscore.Option{Number: oscore.Observe})})
			for i := 0; ; i++ {
				if _, ok := option(m, oscore.Observe); !ok || m.Code != oscore.Content || len(m.Payload) == 0 {
					t.Fatalf("notification %d: %v %q", i, m.Code, m.Payload)
				}
				if i == 2 {
					break
				}
				m = next(t, x, ch)
			}
		})
	}
}

// waitForServer sends requests until the server answers one with something
// other than an Echo challenge, which it answers with the Echo option.
func waitForServer(t *testing.T, c *client, ctx *oscore.Context) {
	var echo []oscore.Option
	for range 50 {
		out, x, err := ctx.ProtectRequest(&oscore.Message{Code: oscore.GET, Options: path("example_data", echo...)})
		if err != nil {
			t.Fatal(err)
		}
		ch, err := c.send(out)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case d := <-ch:
			m, err := x.UnprotectResponse(&d.Message)
			if err != nil {
				t.Fatalf("response: %v", err)
			}
			v, ok := option(m, oscore.Echo)
			if m.Code != oscore.Unauthorized || !ok {
				return
			}
			echo = []oscore.Option{{Number: oscore.Echo, Value: v}}
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("libcoap server did not answer")
}

func TestLibcoapClientGoServer(t *testing.T) {
	for _, s := range libcoapSetups {
		t.Run(s.String(), func(t *testing.T) { runLibcoapClient(t, s, s.config(serverID, clientID)) })
	}
	t.Run("Echo recovery", func(t *testing.T) {
		cfg := libcoapSetups[0].config(serverID, clientID)
		cfg.ReplayWindowLost = true
		runLibcoapClient(t, libcoapSetups[0], cfg)
	})
}

func runLibcoapClient(t *testing.T, s setup, cfg *oscore.Config) {
	bin := libcoapBin(t, "coap-client")
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
	// The sequence file carries the client's Sender Sequence Number from one
	// run to the next.
	conf := s.libcoapConfig(t, clientID, serverID) + "," + filepath.Join(t.TempDir(), "seq")
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{uri + "/hello"}, "Hello World!"},
		{[]string{"-m", "post", "-e", "ping", uri + "/echo"}, "ping"},
		{[]string{"-s", "1", "-B", "2", uri + "/counter"}, "0\n1\n2\n3\n0"},
	} {
		cmd := exec.Command(bin, append([]string{"-E", conf, "-w"}, tt.args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("coap-client %v: %v\n%s", tt.args, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != tt.want {
			t.Errorf("coap-client %v printed %q, want %q", tt.args, got, tt.want)
		}
	}
}
