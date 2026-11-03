package oscore_test

import (
	"errors"
	"fmt"
	"log"

	"github.com/aquilliam/oscore"
)

var (
	masterSecret = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	masterSalt   = []byte{0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40}
)

// newContexts returns the contexts of a client with Sender ID 0x01 and a
// server with Sender ID 0x02.
func newContexts() (client, server *oscore.Context) {
	client, err := oscore.NewContext(&oscore.Config{
		MasterSecret: masterSecret,
		MasterSalt:   masterSalt,
		SenderID:     []byte{0x01},
		RecipientID:  []byte{0x02},
	})
	if err != nil {
		log.Fatal(err)
	}
	server, err = oscore.NewContext(&oscore.Config{
		MasterSecret: masterSecret,
		MasterSalt:   masterSalt,
		SenderID:     []byte{0x02},
		RecipientID:  []byte{0x01},
	})
	if err != nil {
		log.Fatal(err)
	}
	return client, server
}

func Example() {
	client, server := newContexts()

	// The client protects a GET request. The transport sends the result
	// with a new Token.
	req := &oscore.Message{
		Code:    oscore.GET,
		Options: []oscore.Option{{Number: oscore.URIPath, Value: []byte("temperature")}},
	}
	protected, exchange, err := client.ProtectRequest(req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("on the wire:", protected.Code)

	// The server verifies the request and protects its response.
	got, serverExchange, err := server.UnprotectRequest(protected)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("server got:", got.Code, string(got.Options[0].Value))
	resp, err := serverExchange.ProtectResponse(&oscore.Message{Code: oscore.Content, Payload: []byte("21.5 C")})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("on the wire:", resp.Code)

	// The client verifies the response with the same Token.
	answer, err := exchange.UnprotectResponse(resp)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("client got:", answer.Code, string(answer.Payload))
	// Output:
	// on the wire: 0.02
	// server got: 0.01 temperature
	// on the wire: 2.04
	// client got: 2.05 21.5 C
}

// A server with several clients finds the context of each request from its
// kid, and answers with ErrorResponse when a request fails to verify.
func ExampleParseRequestID() {
	client, server := newContexts()
	contexts := map[string]*oscore.Context{string(server.RecipientID()): server}

	handle := func(m *oscore.Message) *oscore.Message {
		id, err := oscore.ParseRequestID(m)
		if err != nil {
			return oscore.ErrorResponse(err)
		}
		ctx := contexts[string(id.KID)]
		if ctx == nil {
			return oscore.ErrorResponse(oscore.ErrUnknownContext)
		}
		req, x, err := ctx.UnprotectRequest(m)
		if err != nil {
			return oscore.ErrorResponse(err)
		}
		resp, err := x.ProtectResponse(&oscore.Message{Code: oscore.Changed, Payload: req.Payload})
		if err != nil {
			return &oscore.Message{Code: oscore.InternalServerError}
		}
		return resp
	}

	protected, _, err := client.ProtectRequest(&oscore.Message{Code: oscore.POST, Payload: []byte("on")})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(handle(protected).Code)
	r := handle(protected) // the same request again
	fmt.Println(r.Code, string(r.Payload))
	// Output:
	// 2.04
	// 4.01 Replay detected
}

// A device that keeps its context across reboots stores Sender Sequence
// Numbers ahead of use, and has the server check the freshness of the first
// request after a reboot with the Echo option.
func ExampleConfig_reserve() {
	var stored uint64 // stands in for nonvolatile memory
	newServer := func(rebooted bool) *oscore.Context {
		ctx, err := oscore.NewContext(&oscore.Config{
			MasterSecret:   masterSecret,
			MasterSalt:     masterSalt,
			SenderID:       []byte{0x02},
			RecipientID:    []byte{0x01},
			SenderSequence: stored,
			Reserve: func(next uint64) error {
				stored = next
				return nil
			},
			ReserveStep:      100,
			ReplayWindowLost: rebooted,
		})
		if err != nil {
			log.Fatal(err)
		}
		return ctx
	}
	client, _ := newContexts()
	server := newServer(false)
	send := func(req *oscore.Message) *oscore.Message {
		protected, x, err := client.ProtectRequest(req)
		if err != nil {
			log.Fatal(err)
		}
		var resp *oscore.Message
		if got, sx, err := server.UnprotectRequest(protected); err != nil {
			resp = oscore.ErrorResponse(err)
		} else if resp, err = sx.ProtectResponse(&oscore.Message{Code: oscore.Content, Payload: got.Payload}); err != nil {
			log.Fatal(err)
		}
		answer, err := x.UnprotectResponse(resp)
		if err != nil {
			log.Fatal(err)
		}
		return answer
	}

	fmt.Println("before the reboot:", send(&oscore.Message{Code: oscore.GET}).Code)

	server = newServer(true)
	answer := send(&oscore.Message{Code: oscore.GET})
	fmt.Println("first request:", answer.Code)
	echo := answer.Options[0]
	answer = send(&oscore.Message{Code: oscore.GET, Options: []oscore.Option{echo}})
	fmt.Println("with Echo:", answer.Code)
	fmt.Println("stored:", stored)
	// Output:
	// before the reboot: 2.05
	// first request: 4.01
	// with Echo: 2.05
	// stored: 100
}

// An Observe registration gets any number of notifications.
func ExampleExchange_UnprotectResponse_observe() {
	client, server := newContexts()
	protected, exchange, err := client.ProtectRequest(&oscore.Message{
		Code: oscore.GET,
		Options: []oscore.Option{
			{Number: oscore.Observe},
			{Number: oscore.URIPath, Value: []byte("temperature")},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	_, serverExchange, err := server.UnprotectRequest(protected)
	if err != nil {
		log.Fatal(err)
	}
	var notifications []*oscore.Message
	for i, v := range []string{"21.5 C", "21.6 C", "21.8 C"} {
		n, err := serverExchange.ProtectResponse(&oscore.Message{
			Code:    oscore.Content,
			Options: []oscore.Option{{Number: oscore.Observe, Value: []byte{byte(i)}}},
			Payload: []byte(v),
		})
		if err != nil {
			log.Fatal(err)
		}
		notifications = append(notifications, n)
	}
	for _, i := range []int{0, 2, 1} { // the second arrives late
		n, err := exchange.UnprotectResponse(notifications[i])
		if errors.Is(err, oscore.ErrReplay) {
			fmt.Println("stale notification dropped")
			continue
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(n.Payload))
	}
	// Output:
	// 21.5 C
	// 21.8 C
	// stale notification dropped
}
