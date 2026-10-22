package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigurn/crc16"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
)

type quicTestDHT struct {
	addresses address.List
	key       ed25519.PublicKey
	findErr   error
}

func (d *quicTestDHT) FindAddresses(context.Context, []byte) (*address.List, ed25519.PublicKey, error) {
	return &d.addresses, d.key, d.findErr
}

func (*quicTestDHT) StoreAddress(context.Context, address.List, time.Duration, ed25519.PrivateKey) (int, []byte, error) {
	return 0, nil, fmt.Errorf("unexpected DHT write")
}

func (*quicTestDHT) Close() {}

type quicTestPeer struct {
	adnl.Peer
	version *atomic.Int32
}

func (p quicTestPeer) SetCustomMessageHandler(handler func(*adnl.MessageCustom) error) {
	p.Peer.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		switch msg.Data.(type) {
		case rldp.MessagePart:
			p.version.Store(1)
		case rldp.MessagePartV2:
			p.version.Store(2)
		}
		return handler(msg)
	})
}

type quicFixture struct {
	transport          *Transport
	host               string
	serverKey          ed25519.PrivateKey
	clientKey          ed25519.PublicKey
	quicSocket         net.PacketConn
	bodies             sync.Map
	capQueries         atomic.Int32
	ignoreCapabilities atomic.Bool
	streamError        atomic.Bool
	holdPayload        atomic.Bool
	payloadStarted     chan struct{}
	payloadResume      chan struct{}
	connections        atomic.Int32
	quicRequests       atomic.Int32
	rldpRequests       atomic.Int32
	pulls              atomic.Int32
	version            atomic.Int32
	badAnswer          atomic.Bool
}

func newQUICFixture(t *testing.T, capabilities int64, ready bool, enableQUIC ...bool) *quicFixture {
	t.Helper()
	serverPub, serverKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, clientKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &quicFixture{serverKey: serverKey, clientKey: clientPub, payloadStarted: make(chan struct{}, 1), payloadResume: make(chan struct{})}
	var adnlSocket net.PacketConn
	for {
		adnlSocket, err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := adnlSocket.LocalAddr().(*net.UDPAddr).Port
		if port <= 64535 {
			f.quicSocket, err = net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port+1000))
			if err == nil {
				break
			}
		}
		_ = adnlSocket.Close()
	}
	t.Cleanup(func() { _ = adnlSocket.Close(); _ = f.quicSocket.Close() })
	server := adnl.NewGatewayWithNetManager(serverKey, adnl.NewSingleNetReader(func(string) (net.PacketConn, error) {
		return adnlSocket, nil
	}))
	t.Cleanup(func() { _ = server.Close() })
	server.SetConnectionHandler(func(peer adnl.Peer) error {
		wrapped := quicTestPeer{Peer: peer, version: &f.version}
		rl := rldp.NewClientV2(wrapped)
		peer.SetQueryHandler(func(query *adnl.MessageQuery) error {
			if _, ok := query.Data.(GetCapabilities); !ok {
				return fmt.Errorf("unexpected ADNL query %T", query.Data)
			}
			f.capQueries.Add(1)
			if f.ignoreCapabilities.Load() {
				return nil
			}
			return peer.Answer(context.Background(), query.ID, Capabilities{Value: capabilities})
		})
		rl.SetOnQuery(func(transferID []byte, query *rldp.Query) error {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, ok := query.Data.(Request); ok {
					f.rldpRequests.Add(1)
				}
				answer, err := f.answer(query.Data, func(req GetNextPayloadPart) (part PayloadPart, err error) {
					err = rl.DoQuery(ctx, _RLDPMaxAnswerSize, req, &part)
					return
				})
				if err == nil {
					_ = rl.SendAnswer(ctx, query.MaxAnswerSize, query.Timeout, query.ID, transferID, answer)
				}
			}()
			return nil
		})
		return nil
	})
	if err = server.StartServer(adnlSocket.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	if ready {
		f.startQUIC(t)
	}
	gate := adnl.NewGatewayWithNetManager(clientKey, adnl.NewSingleNetReader(func(string) (net.PacketConn, error) {
		return net.ListenPacket("udp4", "127.0.0.1:0")
	}))
	if err = gate.StartClient(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close() })
	// Ownership tests need a ready ADNL path, without pre-probing HTTP capabilities.
	peer, err := gate.RegisterClient(adnlSocket.LocalAddr().String(), serverPub)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err = peer.Ping(ctx); err != nil {
		t.Fatalf("ADNL fixture readiness: %v", err)
	}
	enabled := true
	if len(enableQUIC) > 0 {
		enabled = enableQUIC[0]
	}
	f.transport = NewTransport(gate, clientKey, &quicTestDHT{addresses: server.GetAddressList(), key: serverPub}, nil, nil, nil, enabled)
	t.Cleanup(f.transport.Stop)
	if f.transport.quicGate != nil && !bytes.Equal(f.transport.quicGate.PublicKey(), gate.GetPublicKey()) {
		t.Fatal("QUIC identity differs from the ADNL identity")
	}
	raw := append([]byte{0x2d}, server.GetID()...)
	raw = binary.BigEndian.AppendUint16(raw, crc16.Checksum(raw, crc16table))
	f.host = strings.ToLower(base32.StdEncoding.EncodeToString(raw)[1:]) + ".adnl"
	return f
}

func (f *quicFixture) startQUIC(t *testing.T) {
	t.Helper()
	g, err := quic.NewGateway(f.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	g.SetConnectionHandler(func(peer *quic.Peer) error {
		if !bytes.Equal(peer.PeerKey(), f.clientKey) {
			return fmt.Errorf("unexpected QUIC client identity")
		}
		f.connections.Add(1)
		peer.SetQueryHandler(func(ctx context.Context, payload []byte) ([]byte, error) {
			var query any
			if err := parseQUICHTTP(payload, &query); err != nil {
				return nil, err
			}
			if _, ok := query.(GetNextPayloadPart); ok && f.holdPayload.Load() {
				select {
				case f.payloadStarted <- struct{}{}:
				default:
				}
				select {
				case <-f.payloadResume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			if _, ok := query.(Request); ok {
				f.quicRequests.Add(1)
				if f.streamError.Load() {
					return nil, fmt.Errorf("test stream error")
				}
				if f.badAnswer.Load() {
					return []byte{1, 2, 3}, nil
				}
			}
			answer, err := f.answer(query, func(req GetNextPayloadPart) (part PayloadPart, err error) {
				f.pulls.Add(1)
				data, err := tl.Serialize(req, true)
				if err != nil {
					return part, err
				}
				data, err = peer.Query(ctx, data, quic.DefaultMaxObjectSize)
				if err == nil {
					err = parseQUICHTTP(data, &part)
				}
				return part, err
			})
			if err != nil {
				return nil, err
			}
			return tl.Serialize(answer, true)
		})
		return nil
	})
	go func() { _ = g.Serve(f.quicSocket) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = g.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
}

func (f *quicFixture) answer(query any, pull func(GetNextPayloadPart) (PayloadPart, error)) (any, error) {
	switch req := query.(type) {
	case Request:
		body := []byte("hello QUIC")
		if req.Method == http.MethodPost {
			body = nil
			for seqno := int32(0); ; seqno++ {
				part, err := pull(GetNextPayloadPart{ID: req.ID, Seqno: seqno, MaxChunkSize: 16 * 1024})
				if err != nil {
					return nil, err
				}
				body = append(body, part.Data...)
				if part.IsLast {
					break
				}
			}
		}
		f.bodies.Store(string(req.ID), body)
		return Response{Version: "HTTP/1.1", StatusCode: 200, Reason: "OK"}, nil
	case GetNextPayloadPart:
		body, ok := f.bodies.Load(string(req.ID))
		if !ok {
			return nil, fmt.Errorf("unknown response")
		}
		data := body.([]byte)
		offset := int(req.Seqno) * int(req.MaxChunkSize)
		end := min(offset+int(req.MaxChunkSize), len(data))
		return PayloadPart{Data: data[offset:end], IsLast: end == len(data)}, nil
	default:
		return nil, fmt.Errorf("unexpected HTTP query %T", query)
	}
}

func (f *quicFixture) request(method string, body []byte) ([]byte, error) {
	return f.requestHost(f.host, method, body)
}

func (f *quicFixture) requestHost(host, method string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+host+"/", reader)
	if err != nil {
		return nil, err
	}
	response, err := f.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", response.StatusCode)
	}
	return io.ReadAll(response.Body)
}

func waitForQUIC(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("background QUIC state did not become ready")
}

func (f *quicFixture) site(t *testing.T) *siteInfo {
	t.Helper()
	f.transport.mx.RLock()
	site := f.transport.activeSites[f.host]
	f.transport.mx.RUnlock()
	if site == nil {
		t.Fatal("site is missing")
	}
	return site
}

func (f *quicFixture) ready(t *testing.T) *quicClient {
	t.Helper()
	var client *quicClient
	waitForQUIC(t, func() bool {
		site := f.site(t)
		site.mx.RLock()
		defer site.mx.RUnlock()
		client = site.Actor.(*rldpInfo).quicClient
		return client != nil && !client.failed.Load()
	})
	return client
}

func TestQUICHTTPGetAndPost(t *testing.T) {
	f := newQUICFixture(t, 3, true)
	if body, err := f.request(http.MethodGet, nil); err != nil || string(body) != "hello QUIC" {
		t.Fatalf("first GET: %q, %v", body, err)
	}
	if f.rldpRequests.Load() != 1 || f.quicRequests.Load() != 0 {
		t.Fatal("first request did not use RLDP2")
	}
	f.ready(t)
	if body, err := f.request(http.MethodGet, nil); err != nil || string(body) != "hello QUIC" {
		t.Fatalf("QUIC GET: %q, %v", body, err)
	}
	post := bytes.Repeat([]byte("QUIC POST"), 16384)
	if body, err := f.request(http.MethodPost, post); err != nil || !bytes.Equal(body, post) {
		t.Fatalf("POST: %d bytes, %v", len(body), err)
	}
	if f.pulls.Load() < 2 || f.quicRequests.Load() != 2 || f.rldpRequests.Load() != 1 || f.capQueries.Load() != 1 || f.connections.Load() != 1 {
		t.Fatalf("pulls=%d QUIC=%d RLDP=%d probes=%d connections=%d", f.pulls.Load(), f.quicRequests.Load(), f.rldpRequests.Load(), f.capQueries.Load(), f.connections.Load())
	}
}

func TestQUICDialFallbackAndRetry(t *testing.T) {
	f := newQUICFixture(t, 3, false)
	realDial := f.transport.dialQUIC
	var allow atomic.Bool
	var failures atomic.Int32
	f.transport.dialQUIC = func(ctx context.Context, key ed25519.PublicKey, addr string) (*quic.Peer, error) {
		if !allow.Load() {
			failures.Add(1)
			return nil, fmt.Errorf("test dial failure")
		}
		return realDial(ctx, key, addr)
	}
	if _, err := f.request(http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	site := f.site(t)
	waitForQUIC(t, func() bool {
		site.mx.RLock()
		defer site.mx.RUnlock()
		info := site.Actor.(*rldpInfo)
		return failures.Load() > 0 && info.capabilitiesReceived && !info.retryQUICAt.IsZero()
	})
	for range 2 {
		if _, err := f.request(http.MethodGet, nil); err != nil {
			t.Fatal(err)
		}
	}
	if f.rldpRequests.Load() != 3 || f.capQueries.Load() != 1 || f.version.Load() != 2 {
		t.Fatal("RLDP2 fallback or capability cache changed")
	}
	f.startQUIC(t)
	allow.Store(true)
	site.mx.Lock()
	info := site.Actor.(*rldpInfo)
	info.retryQUICAt = time.Now().Add(-time.Second)
	notifyQUIC(info.quicWake)
	site.mx.Unlock()
	waitForQUIC(t, func() bool {
		site.mx.Lock()
		defer site.mx.Unlock()
		info := site.Actor.(*rldpInfo)
		if info.quicClient != nil {
			return true
		}
		info.retryQUICAt = time.Now().Add(-time.Second)
		notifyQUIC(info.quicWake)
		return false
	}) // No request triggers this retry.
	if _, err := f.request(http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	if f.quicRequests.Load() != 1 || f.capQueries.Load() != 1 {
		t.Fatal("dial retry re-probed answered capabilities")
	}
}

func TestPeerWithoutQUICStaysOnRLDP(t *testing.T) {
	for _, caps := range []int64{0, 1} {
		t.Run(fmt.Sprint(caps), func(t *testing.T) {
			f := newQUICFixture(t, caps, true)
			if _, err := f.request(http.MethodGet, nil); err != nil {
				t.Fatal(err)
			}
			site := f.site(t)
			waitForQUIC(t, func() bool {
				site.mx.RLock()
				defer site.mx.RUnlock()
				return site.Actor.(*rldpInfo).capabilitiesReceived
			})
			for range 2 {
				if _, err := f.request(http.MethodGet, nil); err != nil {
					t.Fatal(err)
				}
			}
			if f.quicRequests.Load() != 0 || f.connections.Load() != 0 || f.rldpRequests.Load() != 3 || f.version.Load() != 2 || f.capQueries.Load() != 1 {
				t.Fatal("legacy peer did not stay on RLDP2 with cached capabilities")
			}
		})
	}
}

func TestUnansweredProbeDoesNotBlockRequests(t *testing.T) {
	f := newQUICFixture(t, 3, true)
	f.ignoreCapabilities.Store(true)
	started := time.Now()
	for range 3 {
		if _, err := f.request(http.MethodGet, nil); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(started) > time.Second {
		t.Fatal("requests waited for the three-second capability probe")
	}
	site := f.site(t)
	site.mx.RLock()
	info := site.Actor.(*rldpInfo)
	inProgress, answered := info.inProgress, info.capabilitiesReceived
	site.mx.RUnlock()
	if !inProgress || answered || f.rldpRequests.Load() != 3 || f.quicRequests.Load() != 0 {
		t.Fatal("unanswered peer blocked RLDP2 or launched competing workers")
	}
}

func TestQUICStreamErrorsDoNotRetirePeer(t *testing.T) {
	f := newQUICFixture(t, 3, true)
	if _, err := f.request(http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	client := f.ready(t)
	for _, failure := range []string{"malformed", "stream", "canceled"} {
		before := f.rldpRequests.Load()
		switch failure {
		case "malformed":
			f.badAnswer.Store(true)
		case "stream":
			f.streamError.Store(true)
		case "canceled":
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var response Response
			if err := client.DoQuery(ctx, _RLDPMaxAnswerSize, Request{ID: make([]byte, 32), Method: "GET", URL: "/", Version: "HTTP/1.1"}, &response); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel error: %v", err)
			}
		}
		if failure != "canceled" {
			if _, err := f.request(http.MethodGet, nil); err == nil {
				t.Fatalf("%s error was ignored", failure)
			}
		}
		f.badAnswer.Store(false)
		f.streamError.Store(false)
		if client.failed.Load() || f.rldpRequests.Load() != before {
			t.Fatal("stream failure retired the connection or replayed the query")
		}
		if _, err := f.request(http.MethodGet, nil); err != nil {
			t.Fatal(err)
		}
		if f.ready(t) != client || f.connections.Load() != 1 {
			t.Fatal("shared peer was replaced after one stream failed")
		}
	}
	_ = client.peer.Close()
	waitForQUIC(t, client.failed.Load)
}

func TestTunnelDisablesQUIC(t *testing.T) {
	f := newQUICFixture(t, 3, true, false)
	if f.transport.quicGate != nil {
		t.Fatal("tunnel transport created a direct QUIC gateway")
	}
	for range 2 {
		if _, err := f.request(http.MethodGet, nil); err != nil {
			t.Fatal(err)
		}
	}
	if f.capQueries.Load() != 0 || f.connections.Load() != 0 || f.rldpRequests.Load() != 2 || f.version.Load() != 2 {
		t.Fatal("tunnel transport attempted direct QUIC")
	}
}

func TestQUICIdleAndEndpointCleanup(t *testing.T) {
	f := newQUICFixture(t, 3, true)
	if _, err := f.request(http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	client := f.ready(t)
	site := f.site(t)
	originalDHT := f.transport.dht
	f.transport.dht = &quicTestDHT{findErr: fmt.Errorf("test resolution failure")}
	atomic.StoreInt64(&site.LastSuccess, 0)
	if _, err := f.request(http.MethodGet, nil); err == nil {
		t.Fatal("failed re-resolution was ignored")
	}
	site.mx.RLock()
	preservedAfterError := site.Actor.(*rldpInfo).quicClient == client
	site.mx.RUnlock()
	if !preservedAfterError || client.failed.Load() {
		t.Fatal("one failed request retired the shared peer")
	}
	f.transport.dht = originalDHT
	atomic.StoreInt64(&site.LastSuccess, time.Now().Unix())
	atomic.StoreInt64(&site.QUICLastUsed, time.Now().Add(-_QUICIdleTimeout-time.Second).UnixNano())
	waitForQUIC(t, func() bool { f.transport.cleanIdle(time.Now()); return client.failed.Load() })
	site.mx.RLock()
	empty := site.Actor.(*rldpInfo).quicClient == nil
	site.mx.RUnlock()
	if !empty {
		t.Fatal("idle QUIC client remained published")
	}
	if _, err := f.request(http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	client = f.ready(t)
	site.mx.Lock()
	old := site.Actor.(*rldpInfo)
	same := &rldpInfo{ID: old.ID, Addr: old.Addr, quicAddr: old.quicAddr}
	site.Actor = same
	retired := f.transport.reconcileQUIC(site, old)
	preserved := same.quicClient == client && same.capabilitiesReceived
	site.mx.Unlock()
	if retired != nil || !preserved {
		t.Fatal("same peer lost its cached state")
	}
	site.mx.Lock()
	site.Actor = &rldpInfo{ID: old.ID, Addr: "127.0.0.1:1"}
	retired = f.transport.reconcileQUIC(site, same)
	site.mx.Unlock()
	if retired == nil || retired.client != client {
		t.Fatal("changed endpoint did not retire the old QUIC peer")
	}
	f.transport.releaseQUIC(retired)
	if !client.failed.Load() {
		t.Fatal("old endpoint's QUIC peer remained open")
	}
}

func TestPayloadBoundsAndOverflow(t *testing.T) {
	stream := &payloadStream{Data: io.NopCloser(bytes.NewReader(nil))}
	for _, req := range []GetNextPayloadPart{{Seqno: -1, MaxChunkSize: 1}, {MaxChunkSize: 0}, {MaxChunkSize: -1}, {MaxChunkSize: _MaxPayloadChunkSize + 1}, {Seqno: 1 << 30, MaxChunkSize: 4}} {
		if _, err := handleGetPart(req, stream); err == nil {
			t.Fatalf("invalid bounds accepted: %+v", req)
		}
	}
}

func TestQUICRejectsMalformedPayloadQueries(t *testing.T) {
	f := newQUICFixture(t, 3, true)
	for _, request := range []GetNextPayloadPart{
		{ID: make([]byte, 32), MaxChunkSize: -1},
		{ID: make([]byte, 32), Seqno: -1, MaxChunkSize: 1024},
		{ID: make([]byte, 32), MaxChunkSize: _MaxPayloadChunkSize + 1},
	} {
		wire, err := tl.Serialize(request, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.transport.handleQUICQuery(context.Background(), wire); err == nil {
			t.Fatal("invalid payload request was accepted")
		}
	}
	if _, err := f.transport.handleQUICQuery(context.Background(), []byte{1, 2, 3}); err == nil {
		t.Fatal("truncated payload query was accepted")
	}
}

func TestQUICInFlightSurvivesIdleCleaner(t *testing.T) {
	f := newQUICFixture(t, 3, true)
	f.transport.mx.Lock()
	f.transport.quicIdleTimeout = 10 * time.Millisecond
	f.transport.mx.Unlock()
	if _, err := f.request(http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	client := f.ready(t)
	site := f.site(t)
	// Ordinary requests must not move the upstream RLDP reinit timestamp.
	rldpUsed := time.Now().Add(-5 * time.Second).Unix()
	atomic.StoreInt64(&site.LastUsed, rldpUsed)
	before := atomic.LoadInt64(&site.QUICLastUsed)
	f.holdPayload.Store(true)
	done := make(chan error, 1)
	go func() {
		body, err := f.request(http.MethodGet, nil)
		if err == nil && string(body) != "hello QUIC" {
			err = fmt.Errorf("unexpected streamed body")
		}
		done <- err
	}()
	var resume sync.Once
	release := func() { resume.Do(func() { close(f.payloadResume) }) }
	defer release()
	select {
	case <-f.payloadStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("payload query was not started")
	}
	time.Sleep(60 * time.Millisecond)
	for range 3 {
		f.transport.cleanIdle(time.Now())
	}
	if client.failed.Load() || client.inFlight.Load() != 1 || atomic.LoadInt64(&site.quicInFlight) != 1 {
		t.Fatal("in-flight QUIC transfer was retired")
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not finish")
	}
	waitForQUIC(t, func() bool { return client.inFlight.Load() == 0 })
	if atomic.LoadInt64(&site.QUICLastUsed) <= before {
		t.Fatal("payload parts did not refresh QUIC activity")
	}
	if atomic.LoadInt64(&site.LastUsed) != rldpUsed {
		t.Fatal("QUIC traffic changed the RLDP timestamp")
	}
	atomic.StoreInt64(&site.LastUsed, time.Now().Add(-31*time.Second).Unix())
	if _, err := f.request(http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&site.LastUsed) <= rldpUsed {
		t.Fatal("active QUIC site skipped the upstream RLDP reinit")
	}
	waitForQUIC(t, func() bool { return client.inFlight.Load() == 0 })
	atomic.StoreInt64(&site.QUICLastUsed, time.Now().Add(-time.Second).UnixNano())
	waitForQUIC(t, func() bool {
		f.transport.cleanIdle(time.Now())
		return client.failed.Load()
	})
	site.mx.RLock()
	generation := site.Actor.(*rldpInfo).quicGeneration
	site.mx.RUnlock()
	f.transport.cleanIdle(time.Now())
	site.mx.RLock()
	sameGeneration := site.Actor.(*rldpInfo).quicGeneration == generation
	site.mx.RUnlock()
	if !sameGeneration {
		t.Fatal("cleaner repeatedly stopped an already-stopped worker")
	}
}

func TestQUICSharedPeerOwnership(t *testing.T) {
	f := newQUICFixture(t, 3, true)
	if _, err := f.request(http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	a := f.site(t)
	first := f.ready(t)
	alias := "second.ton"
	a.mx.RLock()
	old := a.Actor.(*rldpInfo)
	bInfo := &rldpInfo{ActiveClient: old.ActiveClient, ID: old.ID, Addr: old.Addr, quicAddr: old.quicAddr, quicWake: make(chan struct{}, 1)}
	a.mx.RUnlock()
	b := &siteInfo{Actor: bInfo, LastUsed: time.Now().Unix(), LastSuccess: time.Now().Unix(), QUICLastUsed: time.Now().UnixNano()}
	f.transport.mx.Lock()
	f.transport.activeSites[alias] = b
	f.transport.mx.Unlock()
	if _, err := f.requestHost(alias, http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	readyBoth := func() *quicClient {
		var shared *quicClient
		waitForQUIC(t, func() bool {
			for _, site := range []*siteInfo{a, b} {
				site.mx.Lock()
				info := site.Actor.(*rldpInfo)
				if info.quicClient == nil {
					info.retryQUICAt = time.Now().Add(-time.Second)
					notifyQUIC(info.quicWake)
				}
				site.mx.Unlock()
			}
			a.mx.RLock()
			ac := a.Actor.(*rldpInfo).quicClient
			a.mx.RUnlock()
			b.mx.RLock()
			bc := b.Actor.(*rldpInfo).quicClient
			b.mx.RUnlock()
			shared = ac
			return ac != nil && ac == bc && !ac.failed.Load()
		})
		return shared
	}
	client := readyBoth()
	if client != first || f.connections.Load() != 1 {
		t.Fatal("two hosts did not share one QUIC connection")
	}
	_ = client.peer.Close()
	waitForQUIC(t, func() bool {
		a.mx.RLock()
		ac := a.Actor.(*rldpInfo).quicClient
		a.mx.RUnlock()
		b.mx.RLock()
		bc := b.Actor.(*rldpInfo).quicClient
		b.mx.RUnlock()
		return ac == nil && bc == nil
	})
	client = readyBoth()
	f.transport.quicMx.Lock()
	references := len(client.owner.users)
	f.transport.quicMx.Unlock()
	if client == first || references != 2 {
		t.Fatalf("disconnect did not replace the shared owner for both users: refs=%d", references)
	}
	atomic.StoreInt64(&a.QUICLastUsed, time.Now().Add(-_QUICIdleTimeout-time.Second).UnixNano())
	waitForQUIC(t, func() bool {
		f.transport.cleanIdle(time.Now())
		a.mx.RLock()
		empty := a.Actor.(*rldpInfo).quicClient == nil
		a.mx.RUnlock()
		return empty
	})
	if client.failed.Load() {
		t.Fatal("idling one host closed the other host's peer")
	}
	if _, err := f.requestHost(alias, http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.request(http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	if readyBoth() != client {
		t.Fatal("reactivated host did not reuse the shared owner")
	}
	a.mx.Lock()
	previous := a.Actor.(*rldpInfo)
	a.Actor = &rldpInfo{ID: previous.ID, Addr: "127.0.0.1:1"}
	retired := f.transport.reconcileQUIC(a, previous)
	a.mx.Unlock()
	if retired == nil || retired.client != client {
		t.Fatal("changed endpoint did not release its reference")
	}
	f.transport.releaseQUIC(retired)
	if client.failed.Load() {
		t.Fatal("one host's re-resolution closed another host's connection")
	}
	if _, err := f.requestHost(alias, http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	b.mx.RLock()
	sameClient := b.Actor.(*rldpInfo).quicClient == client
	b.mx.RUnlock()
	if !sameClient || client.failed.Load() {
		t.Fatal("shared connection was unnecessarily replaced")
	}
}

func TestQUICOverlappingReferences(t *testing.T) {
	f := newQUICFixture(t, 3, true)
	if _, err := f.request(http.MethodGet, nil); err != nil {
		t.Fatal(err)
	}
	client := f.ready(t)
	site := f.site(t)
	site.mx.RLock()
	info := site.Actor.(*rldpInfo)
	site.mx.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	oldUse, err := f.transport.acquireQUIC(ctx, info, info.quicWake)
	if err != nil {
		t.Fatal(err)
	}
	nextUse, err := f.transport.acquireQUIC(ctx, info, info.quicWake)
	if err != nil {
		t.Fatal(err)
	}
	f.transport.releaseQUIC(oldUse)
	f.transport.quicMx.Lock()
	references := len(client.owner.users)
	f.transport.quicMx.Unlock()
	if references != 2 || client.failed.Load() {
		t.Fatal("a canceled acquisition released its successor")
	}
	f.transport.releaseQUIC(nextUse)
	f.transport.quicMx.Lock()
	references = len(client.owner.users)
	f.transport.quicMx.Unlock()
	if references != 1 || client.failed.Load() {
		t.Fatal("temporary references affected the published site")
	}
}
