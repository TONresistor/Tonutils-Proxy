package transport

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/tl"
)

type connectTestClient struct {
	lifecycleTestRLDP
	request chan Request
}

func (c *connectTestClient) DoQuery(ctx context.Context, _ uint64, query, result tl.Serializable) error {
	if req, ok := query.(Request); ok {
		c.request <- req
		*result.(*Response) = Response{StatusCode: 200, NoPayload: false}
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestConnectRetainsUploadUntilTunnelClose(t *testing.T) {
	tr := NewTransport(nil, nil, nil, nil, nil, nil)
	defer tr.Stop()
	client := &connectTestClient{request: make(chan Request, 1)}
	host := "example.ton"
	tr.activeSites[host] = &siteInfo{Actor: &rldpInfo{ActiveClient: client}, LastSuccess: time.Now().Unix()}
	tunnel, err := tr.Connect(context.Background(), host, host+":443")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	req := <-client.request
	tr.mx.RLock()
	count := len(tr.activeRequests)
	tr.mx.RUnlock()
	if count != 1 {
		t.Fatalf("upload removed after CONNECT headers: %d streams", count)
	}
	if req.URL != host+":443" || req.Method != "CONNECT" {
		t.Fatalf("incorrect CONNECT request: %+v", req)
	}
	tr.mx.RLock()
	stream := tr.activeRequests[fmt.Sprintf("%x", req.ID)]
	tr.mx.RUnlock()
	written := make(chan error, 1)
	go func() { _, err := tunnel.Write([]byte("TLS")); written <- err }()
	part, err := handleGetPart(GetNextPayloadPart{Seqno: 0, MaxChunkSize: 8192}, stream)
	if err != nil || string(part.Data) != "TLS" {
		t.Fatalf("upload after headers: part=%+v err=%v", part, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := tunnel.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	part, err = handleGetPart(GetNextPayloadPart{Seqno: 1, MaxChunkSize: 8192}, stream)
	if err != nil || !part.IsLast {
		t.Fatalf("upload EOF: part=%+v err=%v", part, err)
	}
	_ = tunnel.Close()
	tr.mx.RLock()
	count = len(tr.activeRequests)
	tr.mx.RUnlock()
	if count != 0 {
		t.Fatal("CONNECT upload leaked after close")
	}
}

func TestTunnelPayloadAcceptsShortParts(t *testing.T) {
	stream := &payloadStream{Data: io.NopCloser(strings.NewReader("TLS")), Tunnel: true}
	part, err := handleGetPart(GetNextPayloadPart{Seqno: 0, MaxChunkSize: 8192}, stream)
	if err != nil || string(part.Data) != "TLS" {
		t.Fatalf("first part=%+v err=%v", part, err)
	}
	part, err = handleGetPart(GetNextPayloadPart{Seqno: 1, MaxChunkSize: 8192}, stream)
	if err != nil || !part.IsLast {
		t.Fatalf("EOF after short part=%+v err=%v", part, err)
	}
}
