package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-storage/storage"
)

type continuationTestRLDP struct {
	nextAllowed time.Time
	releaseWait time.Duration
}

func (r *continuationTestRLDP) Close() {}
func (r *continuationTestRLDP) DoQuery(_ context.Context, _ uint64, query, result tl.Serializable) error {
	req := query.(GetNextPayloadPart)
	part := result.(*PayloadPart)
	switch req.Seqno {
	case 0:
		part.Data = []byte("first")
		r.nextAllowed = time.Now().Add(r.releaseWait)
		return nil
	case 1:
		if time.Now().Before(r.nextAllowed) {
			return errors.New("previous continuation is still being released")
		}
		part.Data = []byte("second")
		part.IsLast = true
		return nil
	default:
		return errors.New("unexpected continuation")
	}
}
func (r *continuationTestRLDP) SetOnQuery(func([]byte, *rldp.Query) error) {}
func (r *continuationTestRLDP) SetOnDisconnect(func())                     {}
func (r *continuationTestRLDP) SendAnswer(context.Context, uint64, uint32, []byte, []byte, tl.Serializable) error {
	return nil
}
func (r *continuationTestRLDP) GetADNL() rldp.ADNL { return nil }

type lifecycleTestRLDP struct {
	closed  chan struct{}
	once    sync.Once
	onQuery func(context.Context) error
}

func (r *lifecycleTestRLDP) Close() {
	r.once.Do(func() { close(r.closed) })
}

func (r *lifecycleTestRLDP) DoQuery(ctx context.Context, _ uint64, _, _ tl.Serializable) error {
	if r.onQuery != nil {
		return r.onQuery(ctx)
	}
	return nil
}

func (r *lifecycleTestRLDP) SetOnQuery(func([]byte, *rldp.Query) error) {}
func (r *lifecycleTestRLDP) SetOnDisconnect(func())                     {}
func (r *lifecycleTestRLDP) SendAnswer(context.Context, uint64, uint32, []byte, []byte, tl.Serializable) error {
	return nil
}
func (r *lifecycleTestRLDP) GetADNL() rldp.ADNL { return nil }

type lifecycleTestDownloader struct {
	ctx        context.Context
	closed     atomic.Bool
	closeCount atomic.Int32
}

func (d *lifecycleTestDownloader) Close() {
	d.closed.Store(true)
	d.closeCount.Add(1)
}
func (d *lifecycleTestDownloader) IsActive() bool { return !d.closed.Load() && d.ctx.Err() == nil }

type payloadTestBody struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (b *payloadTestBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func (b *payloadTestBody) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func TestOrderedRLDPAddressesContinueAfterLastUsed(t *testing.T) {
	addresses := []string{"192.0.2.1:1234", "192.0.2.2:1234", "[2001:db8::1]:1234"}
	got := orderedRLDPAddresses(addresses, addresses[0])
	want := []string{addresses[1], addresses[2], addresses[0]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected address order: got %v, want %v", got, want)
	}
}

func TestRLDPAddressesAcceptOnlyDialableUDPRecords(t *testing.T) {
	records := []address.Address{
		address.UDP{IP: net.ParseIP("192.0.2.1"), Port: 1234},
		address.UDP6{IP: net.ParseIP("2001:db8::1"), Port: 1234},
		address.QUIC{IP: net.ParseIP("192.0.2.2"), Port: 1234},
		address.UDP{IP: net.ParseIP("192.0.2.1"), Port: 1234},
		address.UDP{IP: net.IPv4zero, Port: 1234},
		address.UDP{IP: net.ParseIP("192.0.2.3"), Port: 0},
	}

	got := rldpAddresses(records)
	want := []string{"192.0.2.1:1234", "[2001:db8::1]:1234"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected dialable addresses: got %v, want %v", got, want)
	}
}

func requestHeader(request Request, name string) string {
	for _, header := range request.Headers {
		if http.CanonicalHeaderKey(header.Name) == http.CanonicalHeaderKey(name) {
			return header.Value
		}
	}
	return ""
}

func TestBuildRLDPRequestSignalsKnownAndStreamingBodies(t *testing.T) {
	known := &http.Request{
		Method:        http.MethodPost,
		URL:           &url.URL{Host: "site.ton", Path: "/upload"},
		Host:          "site.ton",
		Header:        http.Header{"Content-Length": {"999"}, "Transfer-Encoding": {"gzip"}},
		Body:          io.NopCloser(strings.NewReader("abc")),
		ContentLength: 3,
	}
	knownRequest := buildRLDPRequest(make([]byte, 32), "site.ton", known)
	if got := requestHeader(knownRequest, "Content-Length"); got != "3" {
		t.Fatalf("unexpected content length %q", got)
	}
	if got := requestHeader(knownRequest, "Transfer-Encoding"); got != "" {
		t.Fatalf("unexpected transfer encoding %q", got)
	}

	streaming := known.Clone(context.Background())
	streaming.Body = io.NopCloser(strings.NewReader("abc"))
	streaming.ContentLength = -1
	streamingRequest := buildRLDPRequest(make([]byte, 32), "site.ton", streaming)
	if got := requestHeader(streamingRequest, "Transfer-Encoding"); got != "chunked" {
		t.Fatalf("unexpected transfer encoding %q", got)
	}
	if got := requestHeader(streamingRequest, "Content-Length"); got != "" {
		t.Fatalf("unexpected content length %q", got)
	}

	empty := known.Clone(context.Background())
	empty.Body = http.NoBody
	empty.ContentLength = 0
	emptyRequest := buildRLDPRequest(make([]byte, 32), "site.ton", empty)
	if requestHeader(emptyRequest, "Content-Length") != "" || requestHeader(emptyRequest, "Transfer-Encoding") != "" {
		t.Fatal("empty request advertised a payload")
	}
}

func TestRequestPayloadCloseUnblocksPump(t *testing.T) {
	body := &payloadTestBody{started: make(chan struct{}), closed: make(chan struct{})}
	payload := newRequestPayload(body)
	<-body.started

	deadline := time.Now().Add(time.Second)
	for len(payload.stream.parts) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(payload.stream.parts) == 0 {
		t.Fatal("payload pump did not fill the stream")
	}

	payload.close()
	select {
	case <-payload.done:
	case <-time.After(time.Second):
		t.Fatal("payload pump did not stop")
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("request body was not closed")
	}
}

func TestRetryPolicyRejectsRequestBodies(t *testing.T) {
	if !canRetryRequest(&http.Request{Method: http.MethodGet, Body: http.NoBody}) {
		t.Fatal("bodyless GET should be retryable")
	}
	if !canRetryRequest(&http.Request{Method: http.MethodHead}) {
		t.Fatal("bodyless HEAD should be retryable")
	}
	if canRetryRequest(&http.Request{Method: http.MethodPost, Body: http.NoBody}) {
		t.Fatal("POST should not be retryable")
	}
	if canRetryRequest(&http.Request{Method: http.MethodGet, Body: io.NopCloser(strings.NewReader("body"))}) {
		t.Fatal("request with a body should not be retryable")
	}
}

func TestFetchRLDPPayloadWaitsForPreviousContinuationRelease(t *testing.T) {
	stream := newDataStreamer()
	response := &http.Response{Trailer: make(http.Header)}
	done := make(chan error, 1)
	go func() {
		err := fetchRLDPPayload(context.Background(), &continuationTestRLDP{releaseWait: _RLDPContinuationDelay * 3 / 4}, make([]byte, 32), response, stream, _RLDPContinuationDelay)
		if err != nil {
			_ = stream.Close()
		}
		done <- err
	}()

	got, readErr := io.ReadAll(stream)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("firstsecond")) {
		t.Fatalf("unexpected streamed payload %q", got)
	}
}

func TestSnapshotActiveSitesSupportsConcurrentMutation(t *testing.T) {
	transport := &Transport{activeSites: map[string]*siteInfo{}}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			transport.mx.Lock()
			transport.activeSites["site.ton"] = &siteInfo{}
			delete(transport.activeSites, "site.ton")
			transport.mx.Unlock()
		}()
		go func() {
			defer wg.Done()
			_ = transport.snapshotActiveSites()
		}()
	}
	wg.Wait()
}

func TestIdleSiteCleanupWaitsForResponseBody(t *testing.T) {
	now := time.Now().Unix()
	transport := &Transport{activeSites: map[string]*siteInfo{}}
	site := transport.acquireSite("site.ton")
	atomic.StoreInt64(&site.LastUsed, now-600)

	transport.cleanIdleSites(now)
	if transport.activeSites["site.ton"] != site {
		t.Fatal("in-flight site was evicted")
	}

	response := &http.Response{Body: io.NopCloser(strings.NewReader("ok"))}
	release := sync.OnceFunc(func() { transport.releaseSite(site) })
	response = holdSiteUntilResponseClose(response, release)
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	atomic.StoreInt64(&site.LastUsed, now-600)
	transport.cleanIdleSites(now)
	if _, ok := transport.activeSites["site.ton"]; ok {
		t.Fatal("idle site was not evicted after response completion")
	}
}

func TestIdleNilActorIsEvicted(t *testing.T) {
	now := time.Now().Unix()
	transport := &Transport{activeSites: map[string]*siteInfo{
		"idle.ton": {LastUsed: now - 600},
	}}
	transport.cleanIdleSites(now)
	if _, ok := transport.activeSites["idle.ton"]; ok {
		t.Fatal("idle site without an actor was not evicted")
	}
}

func TestIdleStorageActorIsClosedAndRemoved(t *testing.T) {
	now := time.Now().Unix()
	store := NewVirtualStorage()
	torrent := storage.NewTorrent("", store, nil)
	torrent.BagID = bytes.Repeat([]byte{1}, 32)
	if err := store.SetTorrent(torrent); err != nil {
		t.Fatal(err)
	}
	downloaderCtx, stop := context.WithCancel(context.Background())
	downloader := &lifecycleTestDownloader{ctx: downloaderCtx}
	bag := &bagInfo{
		key:        "storage",
		torrent:    torrent,
		downloader: downloader,
		stop:       stop,
		references: 1,
		lastUsed:   now - 600,
	}
	transport := &Transport{
		store: store,
		storageBags: map[string]*bagInfo{
			bag.key: bag,
		},
		activeSites: map[string]*siteInfo{
			"storage.ton": {Actor: bag, LastUsed: now - 600},
		},
	}

	transport.cleanIdleSites(now)
	transport.cleanIdleStorageBags(now)
	bag.close()
	if downloader.closeCount.Load() != 1 {
		t.Fatalf("storage downloader closed %d times", downloader.closeCount.Load())
	}
	if len(store.GetAll()) != 0 {
		t.Fatal("idle torrent remained registered")
	}
}

func TestStorageBagIsSharedByBagID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		globalCtx, cancelGlobal := context.WithCancel(t.Context())
		defer cancelGlobal()

		started := make(chan struct{})
		release := make(chan struct{})
		var startedOnce sync.Once
		var creates atomic.Int32
		transport := &Transport{
			globalCtx:    globalCtx,
			storageBags:  map[string]*bagInfo{},
			storageLoads: map[string]*bagLoad{},
			createBagFn: func(context.Context, []byte, string) (*bagInfo, error) {
				creates.Add(1)
				startedOnce.Do(func() { close(started) })
				<-release
				return &bagInfo{}, nil
			},
		}
		bagID := bytes.Repeat([]byte{1}, 32)
		type result struct {
			bag *bagInfo
			err error
		}
		results := make(chan result, 2)
		go func() {
			bag, err := transport.getOrCreateStorageBag(t.Context(), bagID, "first.ton")
			results <- result{bag: bag, err: err}
		}()
		<-started
		go func() {
			bag, err := transport.getOrCreateStorageBag(t.Context(), bagID, "second.ton")
			results <- result{bag: bag, err: err}
		}()
		synctest.Wait()
		close(release)
		synctest.Wait()

		first := <-results
		second := <-results
		if first.err != nil || second.err != nil {
			t.Fatalf("storage bag acquisition failed: %v, %v", first.err, second.err)
		}
		if first.bag != second.bag {
			t.Fatal("the same BagID created multiple storage bags")
		}
		if creates.Load() != 1 {
			t.Fatalf("storage bag was created %d times", creates.Load())
		}
		first.bag.mx.Lock()
		references := first.bag.references
		first.bag.mx.Unlock()
		if references != 2 {
			t.Fatalf("shared storage bag has %d references", references)
		}
	})
}

func TestStorageActorIsNotClosedWhileAnotherResponseUsesIt(t *testing.T) {
	downloader := &lifecycleTestDownloader{ctx: context.Background()}
	bag := &bagInfo{key: "storage", downloader: downloader, references: 1}
	site := &siteInfo{Actor: bag, inFlight: 2}
	transport := &Transport{storageBags: map[string]*bagInfo{bag.key: bag}}

	transport.clearActor(site, bag)
	if site.Actor != bag || downloader.closeCount.Load() != 0 {
		t.Fatal("storage actor was retired while another response was active")
	}

	atomic.StoreInt64(&site.inFlight, 1)
	transport.clearActor(site, bag)
	if site.Actor != nil || downloader.closeCount.Load() != 1 {
		t.Fatal("unused storage actor was not retired")
	}
}

func TestCleanerClosesIdleRLDP(t *testing.T) {
	now := time.Now().Unix()
	client := &lifecycleTestRLDP{closed: make(chan struct{})}
	shared := &rldpInfo{
		ActiveClient: client,
		LastUsed:     now - 600,
		references:   1,
	}
	transport := &Transport{
		activeSites: map[string]*siteInfo{
			"idle.ton": {
				Actor:    shared,
				LastUsed: now - 600,
			},
		},
		rldpClients: map[string]*rldpInfo{"server": shared},
	}

	transport.cleanIdleSites(now)
	transport.cleanIdleRLDPClients(now)
	select {
	case <-client.closed:
	default:
		t.Fatal("idle RLDP client was not closed")
	}

	if _, ok := transport.activeSites["idle.ton"]; ok {
		t.Fatal("idle RLDP site was not evicted")
	}
}

func TestSharedRLDPClientIsReusedByServerKey(t *testing.T) {
	var dials atomic.Int32
	client := &lifecycleTestRLDP{closed: make(chan struct{})}
	serverKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))

	transport := &Transport{
		rldpClients: map[string]*rldpInfo{},
		connectRLDPFn: func(ed25519.PublicKey, string) (RLDP, error) {
			dials.Add(1)
			return client, nil
		},
	}

	first, err := transport.getOrConnectRLDP(serverKey, "127.0.0.1:12336")
	if err != nil {
		t.Fatal(err)
	}
	second, err := transport.getOrConnectRLDP(serverKey, "127.0.0.1:12336")
	if err != nil {
		t.Fatal(err)
	}

	if first != second {
		t.Fatal("domains sharing one ADNL server received different RLDP pools")
	}
	if dials.Load() != 1 {
		t.Fatalf("expected one RLDP client for one server key, got %d", dials.Load())
	}
}

func TestPrepareSiteUsesCurrentPooledRLDPInfo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	now := time.Now().Unix()
	serverKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	old := &rldpInfo{ID: serverKey, Addr: "127.0.0.1:12336", LastUsed: now, references: 1}
	client := &lifecycleTestRLDP{closed: make(chan struct{})}
	current := &rldpInfo{ID: serverKey, Addr: "127.0.0.1:12336", ActiveClient: client, LastUsed: now}
	site := &siteInfo{Actor: old, LastUsed: now, LastSuccess: now}
	transport := &Transport{
		activeSites: map[string]*siteInfo{"site.ton": site},
		rldpClients: map[string]*rldpInfo{strings.Repeat("00", ed25519.PublicKeySize): current},
		globalCtx:   ctx,
	}
	request := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Host: "site.ton", Path: "/"},
		Host:   "site.ton",
		Header: make(http.Header),
		Body:   http.NoBody,
	}

	prepared, err := transport.prepareSite(site, request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.rldp != current || prepared.client != client {
		t.Fatal("site kept an orphaned RLDP pool entry")
	}
	if site.Actor != current {
		t.Fatal("site actor was not updated to the pooled RLDP entry")
	}
	if atomic.LoadInt64(&old.references) != 0 || atomic.LoadInt64(&current.references) != 1 {
		t.Fatal("RLDP actor references were not transferred")
	}
}

func TestRoundTripDoesNotRetryRequestBody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var queries atomic.Int32
	client := &lifecycleTestRLDP{
		closed: make(chan struct{}),
		onQuery: func(context.Context) error {
			queries.Add(1)
			return errors.New("query failed")
		},
	}
	now := time.Now().Unix()
	shared := &rldpInfo{ActiveClient: client, LastUsed: now, references: 1}
	transport := &Transport{
		activeSites: map[string]*siteInfo{
			"site.ton": {Actor: shared, LastUsed: now, LastSuccess: now},
		},
		rldpClients:    map[string]*rldpInfo{"server": shared},
		activeRequests: map[string]*payloadStream{},
		globalCtx:      ctx,
	}
	request := &http.Request{
		Method:        http.MethodPost,
		URL:           &url.URL{Host: "site.ton", Path: "/upload"},
		Host:          "site.ton",
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("payload")),
		ContentLength: 7,
	}

	_, err := transport.RoundTrip(request)
	if err == nil {
		t.Fatal("expected request failure")
	}
	if queries.Load() != 1 {
		t.Fatalf("request body was queried %d times", queries.Load())
	}
}

func TestCreatePersistentDownloaderCancelsPendingCreationWithRequest(t *testing.T) {
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	globalCtx, cancelGlobal := context.WithCancel(context.Background())
	defer cancelGlobal()

	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, _, err := createPersistentDownloader(requestCtx, globalCtx, func(ctx context.Context) (storage.TorrentDownloader, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		result <- err
	}()

	<-started
	cancelRequest()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected request cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending downloader creation did not stop with the request")
	}
}

func TestCreatePersistentDownloaderSurvivesCompletedRequest(t *testing.T) {
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	globalCtx, cancelGlobal := context.WithCancel(context.Background())
	defer cancelGlobal()

	var downloaderCtx context.Context
	downloader, stop, err := createPersistentDownloader(requestCtx, globalCtx, func(ctx context.Context) (storage.TorrentDownloader, error) {
		downloaderCtx = ctx
		return &lifecycleTestDownloader{ctx: ctx}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer downloader.Close()

	cancelRequest()
	select {
	case <-downloaderCtx.Done():
		t.Fatal("completed request canceled the cached downloader")
	default:
	}

	stop()
	select {
	case <-downloaderCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("cached downloader did not stop")
	}
}

func TestCreatePersistentDownloaderClosesLateSuccessAfterCancellation(t *testing.T) {
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	globalCtx, cancelGlobal := context.WithCancel(context.Background())
	defer cancelGlobal()

	started := make(chan struct{})
	release := make(chan struct{})
	downloader := &lifecycleTestDownloader{ctx: globalCtx}
	result := make(chan error, 1)
	go func() {
		_, _, err := createPersistentDownloader(requestCtx, globalCtx, func(context.Context) (storage.TorrentDownloader, error) {
			close(started)
			<-release
			return downloader, nil
		})
		result <- err
	}()

	<-started
	cancelRequest()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected request cancellation, got %v", err)
	}
	close(release)

	deadline := time.After(time.Second)
	for !downloader.closed.Load() {
		select {
		case <-deadline:
			t.Fatal("late downloader success was not closed")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestCanceledRequestDoesNotCloseSharedRLDPClient(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	client := &lifecycleTestRLDP{
		closed: make(chan struct{}),
		onQuery: func(ctx context.Context) error {
			cancelRequest()
			return ctx.Err()
		},
	}
	now := time.Now().Unix()
	shared := &rldpInfo{ActiveClient: client, LastUsed: now, references: 1}
	transport := &Transport{
		activeSites: map[string]*siteInfo{
			"site.ton": {Actor: shared, LastUsed: now, LastSuccess: now},
		},
		rldpClients: map[string]*rldpInfo{"server": shared},
		globalCtx:   ctx,
	}

	request := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Host: "site.ton", Path: "/"},
		Host:   "site.ton",
		Header: make(http.Header),
	}
	request = request.WithContext(requestCtx)

	_, err := transport.RoundTrip(request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected request cancellation, got %v", err)
	}
	select {
	case <-client.closed:
		t.Fatal("request cancellation closed a shared RLDP client")
	default:
	}
}

func TestRetryDoesNotCloseReplacementSharedRLDPClient(t *testing.T) {
	globalCtx, cancelGlobal := context.WithCancel(context.Background())
	defer cancelGlobal()

	replacement := &lifecycleTestRLDP{closed: make(chan struct{})}
	var shared *rldpInfo
	failed := &lifecycleTestRLDP{
		closed: make(chan struct{}),
		onQuery: func(context.Context) error {
			shared.mx.Lock()
			shared.ActiveClient = replacement
			shared.mx.Unlock()
			cancelGlobal()
			return errors.New("stale request failed")
		},
	}
	now := time.Now().Unix()
	shared = &rldpInfo{ActiveClient: failed, LastUsed: now, references: 1}
	transport := &Transport{
		activeSites: map[string]*siteInfo{
			"site.ton": {Actor: shared, LastUsed: now, LastSuccess: now},
		},
		rldpClients: map[string]*rldpInfo{"server": shared},
		globalCtx:   globalCtx,
	}

	request := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Host: "site.ton", Path: "/"},
		Host:   "site.ton",
		Header: make(http.Header),
	}

	_, _ = transport.RoundTrip(request)
	select {
	case <-replacement.closed:
		t.Fatal("retry closed a replacement shared RLDP client")
	default:
	}
}
