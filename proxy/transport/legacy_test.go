package transport

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/rldp"
)

func TestConnectHTTPAcceptsLegacyZeroCapabilities(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, serverKey, _ := ed25519.GenerateKey(nil)
	server := adnl.NewGateway(serverKey)
	defer server.Close()
	server.SetConnectionHandler(func(peer adnl.Peer) error {
		peer.SetQueryHandler(func(q *adnl.MessageQuery) error { return peer.Answer(ctx, q.ID, Capabilities{Value: 0}) })
		legacy := rldp.NewClient(peer)
		legacy.SetOnQuery(func(transfer []byte, q *rldp.Query) error {
			return legacy.SendAnswer(ctx, q.MaxAnswerSize, q.Timeout, q.ID, transfer, Response{Version: "HTTP/1.1", StatusCode: 200, NoPayload: true})
		})
		return nil
	})
	reserve, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserve.LocalAddr().String()
	_ = reserve.Close()
	if err = server.StartServer(addr); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(nil)
	gate := adnl.NewGateway(key)
	if err = gate.StartClient(); err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	tr := NewTransport(gate, nil, nil, nil, nil, nil)
	defer tr.Stop()
	if err = tr.EnableQUIC(key); err != nil {
		t.Fatal(err)
	}
	client, err := tr.connectHTTP(serverKey.Public().(ed25519.PublicKey), addr, "")
	if err != nil {
		t.Fatalf("legacy capability negotiation: %v", err)
	}
	defer client.Close()
	var response Response
	if err = client.DoQuery(ctx, 1024, Request{ID: make([]byte, 32), Method: "GET", URL: "/", Version: "HTTP/1.1"}, &response); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("legacy status %d", response.StatusCode)
	}
}
