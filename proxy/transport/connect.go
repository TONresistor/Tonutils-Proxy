package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Tunnel is a duplex TON HTTP CONNECT stream. CloseWrite sends an upload EOF
// while allowing the peer's remaining response bytes to be read.
type Tunnel struct {
	reader *io.PipeReader
	writer net.Conn
	close  func()
}

func (t *Tunnel) Read(p []byte) (int, error)  { return t.reader.Read(p) }
func (t *Tunnel) Write(p []byte) (int, error) { return t.writer.Write(p) }
func (t *Tunnel) CloseWrite() error           { return t.writer.Close() }
func (t *Tunnel) Close() error                { t.close(); return nil }

type tunnelReader struct{ net.Conn }

func (r tunnelReader) Read(p []byte) (int, error) {
	_ = r.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err := r.Conn.Read(p)
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return n, nil
	}
	return n, err
}

// Connect opens a tunnel to authority through the TON site identified by host.
func (t *Transport) Connect(ctx context.Context, host, authority string) (*Tunnel, error) {
	_, port, err := net.SplitHostPort(authority)
	if err != nil {
		return nil, fmt.Errorf("invalid CONNECT authority: %w", err)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return nil, fmt.Errorf("invalid CONNECT port")
	}
	ctx, cancel := context.WithCancel(ctx)
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "http", Host: host}, Host: authority, Header: make(http.Header)}
	request = request.WithContext(ctx)
	site := t.acquireSite(host)
	prepared, err := t.prepareSite(site, request)
	if err != nil {
		t.releaseSite(site)
		cancel()
		return nil, err
	}
	if prepared.client == nil {
		t.releaseSite(site)
		cancel()
		return nil, fmt.Errorf("CONNECT requires an ADNL site")
	}
	id := make([]byte, 32)
	if _, err = rand.Read(id); err != nil {
		t.releaseSite(site)
		cancel()
		return nil, err
	}
	upload, uploadReader := net.Pipe()
	downloadReader, download := io.Pipe()
	key := hex.EncodeToString(id)
	t.mx.Lock()
	t.activeRequests[key] = &payloadStream{Data: tunnelReader{uploadReader}, Tunnel: true}
	t.mx.Unlock()
	closeTunnel := sync.OnceFunc(func() {
		cancel()
		_ = upload.Close()
		_ = uploadReader.Close()
		_ = download.Close()
		_ = downloadReader.Close()
		t.mx.Lock()
		delete(t.activeRequests, key)
		t.mx.Unlock()
		t.releaseSite(site)
	})
	context.AfterFunc(ctx, closeTunnel)
	var response Response
	err = prepared.client.DoQuery(ctx, _RLDPMaxAnswerSize, Request{ID: id, Method: http.MethodConnect, URL: authority, Version: "HTTP/1.1", Headers: []Header{{Name: "Host", Value: authority}}}, &response)
	if err != nil {
		closeTunnel()
		return nil, err
	}
	if response.StatusCode != http.StatusOK || response.NoPayload {
		closeTunnel()
		return nil, fmt.Errorf("CONNECT rejected: %d %s", response.StatusCode, response.Reason)
	}
	go func() {
		defer download.Close()
		for seq := int32(0); ; seq++ {
			var part PayloadPart
			err := prepared.client.DoQuery(ctx, _RLDPMaxAnswerSize, GetNextPayloadPart{ID: id, Seqno: seq, MaxChunkSize: _ChunkSize}, &part)
			if err != nil {
				_ = download.CloseWithError(err)
				return
			}
			if _, err = download.Write(part.Data); err != nil {
				return
			}
			if part.IsLast {
				return
			}
		}
	}()
	return &Tunnel{reader: downloadReader, writer: upload, close: closeTunnel}, nil
}
