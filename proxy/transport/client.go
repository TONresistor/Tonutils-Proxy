package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/ton/dns"
	"github.com/xssnick/tonutils-storage/storage"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const _ChunkSize = 1 << 17
const _RLDPMaxAnswerSize = 2*_ChunkSize + 1024

const _DHTFindTimeout = 10 * time.Second
const _RoundTripMaxRetries = 2
const _RLDPContinuationDelay = 5 * time.Millisecond

// blockedResponseHeaders prevents malicious TON sites from injecting
// dangerous headers into the HTTP response sent to the user's browser.
var blockedResponseHeaders = map[string]bool{
	"X-Forwarded-For":             true, // proxy topology
	"X-Forwarded-Host":            true,
	"X-Forwarded-Proto":           true,
	"X-Real-Ip":                   true,
	"Forwarded":                   true,
	"Via":                         true,
	"Connection":                  true, // hop-by-hop
	"Keep-Alive":                  true,
	"Proxy-Authenticate":          true,
	"Proxy-Authorization":         true,
	"Transfer-Encoding":           true,
	"Upgrade":                     true,
	"Public-Key-Pins":             true, // security policy injection
	"Public-Key-Pins-Report-Only": true,
}

func isBlockedResponseHeader(name string) bool {
	return blockedResponseHeaders[http.CanonicalHeaderKey(name)]
}

type DHT interface {
	StoreAddress(ctx context.Context, addresses address.List, ttl time.Duration, ownerKey ed25519.PrivateKey) (int, []byte, error)
	FindAddresses(ctx context.Context, key []byte) (*address.List, ed25519.PublicKey, error)
	Close()
}

type Resolver interface {
	Resolve(ctx context.Context, domain string) (*dns.Domain, error)
}

type RLDP interface {
	Close()
	DoQuery(ctx context.Context, maxAnswerSize uint64, query, result tl.Serializable) error
	SetOnQuery(handler func(transferId []byte, query *rldp.Query) error)
	SetOnDisconnect(handler func())
	SendAnswer(ctx context.Context, maxAnswerSize uint64, timeoutAt uint32, queryId, transferId []byte, answer tl.Serializable) error
	GetADNL() rldp.ADNL
}

type ADNL interface {
	RemoteAddr() string
	GetID() []byte
	Query(ctx context.Context, req, result tl.Serializable) error
	SetCustomMessageHandler(handler func(msg *adnl.MessageCustom) error)
	SetDisconnectHandler(handler func(addr string, key ed25519.PublicKey))
	GetDisconnectHandler() func(addr string, key ed25519.PublicKey)
	SendCustomMessage(ctx context.Context, req tl.Serializable) error
	GetCloserCtx() context.Context
	Close()
}

type bagInfo struct {
	key        string
	torrent    *storage.Torrent
	downloader storage.TorrentDownloader
	stop       context.CancelFunc
	mx         sync.Mutex
	references int64
	lastUsed   int64
	invalid    bool
	closeOnce  sync.Once
}

func (b *bagInfo) close() {
	b.closeOnce.Do(func() {
		if b.stop != nil {
			b.stop()
		}
		if b.downloader != nil {
			b.downloader.Close()
		}
		if b.torrent != nil {
			b.torrent.Stop()
		}
	})
}

type downloaderResult struct {
	downloader storage.TorrentDownloader
	err        error
}

type bagLoad struct {
	done chan struct{}
}

func createPersistentDownloader(requestCtx, globalCtx context.Context, create func(context.Context) (storage.TorrentDownloader, error)) (storage.TorrentDownloader, context.CancelFunc, error) {
	downloaderCtx, stop := context.WithCancel(globalCtx)
	result := make(chan downloaderResult)
	abandoned := make(chan struct{})
	go func() {
		downloader, err := create(downloaderCtx)
		select {
		case result <- downloaderResult{downloader: downloader, err: err}:
		case <-abandoned:
			if downloader != nil {
				downloader.Close()
			}
		}
	}()

	select {
	case res := <-result:
		if res.err != nil {
			stop()
			return nil, nil, res.err
		}
		if res.downloader == nil {
			stop()
			return nil, nil, errors.New("storage downloader is nil")
		}
		return res.downloader, stop, nil
	case <-requestCtx.Done():
		close(abandoned)
		stop()
		return nil, nil, requestCtx.Err()
	case <-globalCtx.Done():
		close(abandoned)
		stop()
		return nil, nil, globalCtx.Err()
	}
}

var newRLDP = func(a ADNL) RLDP {
	return rldp.NewClientV2(a)
}

type siteInfo struct {
	Actor any

	LastUsed    int64
	LastSuccess int64
	inFlight    int64
	mx          sync.RWMutex
}

type rldpInfo struct {
	mx sync.Mutex

	ActiveClient RLDP
	LastUsed     int64
	references   int64

	ID   ed25519.PublicKey
	Addr string
}

type Transport struct {
	dht              DHT
	resolver         Resolver
	pool             *liteclient.ConnectionPool
	storageConnector storage.NetConnector
	store            *VirtualStorage
	gate             *adnl.Gateway

	activeSites   map[string]*siteInfo
	rldpClients   map[string]*rldpInfo
	connectRLDPFn func(key ed25519.PublicKey, addr string) (RLDP, error)
	storageBags   map[string]*bagInfo
	storageLoads  map[string]*bagLoad
	createBagFn   func(ctx context.Context, id []byte, host string) (*bagInfo, error)

	activeRequests map[string]*payloadStream
	globalCtx      context.Context
	stop           func()
	mx             sync.RWMutex
}

func NewTransport(gate *adnl.Gateway, dht DHT, resolver Resolver, pool *liteclient.ConnectionPool, storeConn storage.NetConnector, store *VirtualStorage) *Transport {
	t := &Transport{
		gate:             gate,
		dht:              dht,
		resolver:         resolver,
		pool:             pool,
		storageConnector: storeConn,
		store:            store,
		activeRequests:   map[string]*payloadStream{},
		activeSites:      map[string]*siteInfo{},
		rldpClients:      map[string]*rldpInfo{},
		storageBags:      map[string]*bagInfo{},
		storageLoads:     map[string]*bagLoad{},
	}
	t.globalCtx, t.stop = context.WithCancel(context.Background())
	go t.cleaner()
	return t
}

func (t *Transport) Stop() {
	t.stop()
}

func (t *Transport) acquireSite(host string) *siteInfo {
	now := time.Now().Unix()
	t.mx.Lock()
	site := t.activeSites[host]
	if site == nil {
		site = &siteInfo{}
		t.activeSites[host] = site
	}
	atomic.StoreInt64(&site.LastUsed, now)
	atomic.AddInt64(&site.inFlight, 1)
	t.mx.Unlock()
	return site
}

func (t *Transport) releaseSite(site *siteInfo) {
	atomic.StoreInt64(&site.LastUsed, time.Now().Unix())
	atomic.AddInt64(&site.inFlight, -1)
}

func retainActor(actor any) {
	if info, ok := actor.(*rldpInfo); ok && info != nil {
		atomic.AddInt64(&info.references, 1)
	}
}

func releaseActor(actor any) *bagInfo {
	switch info := actor.(type) {
	case *rldpInfo:
		if info != nil {
			atomic.AddInt64(&info.references, -1)
		}
	case *bagInfo:
		if info != nil {
			info.mx.Lock()
			info.references--
			closeBag := info.invalid && info.references == 0
			info.mx.Unlock()
			if closeBag {
				return info
			}
		}
	}
	return nil
}

func swapActorLocked(site *siteInfo, next any) *bagInfo {
	if site.Actor == next {
		return nil
	}
	retainActor(next)
	previous := site.Actor
	site.Actor = next
	return releaseActor(previous)
}

func swapRetainedBagLocked(site *siteInfo, next *bagInfo) *bagInfo {
	if site.Actor == next {
		return releaseActor(next)
	}
	previous := site.Actor
	site.Actor = next
	return releaseActor(previous)
}

func (t *Transport) closeBag(bag *bagInfo) {
	if bag == nil {
		return
	}
	bag.close()
	if t.store != nil && bag.torrent != nil {
		t.store.RemoveTorrent(bag.torrent)
	}
}

func (t *Transport) invalidateBag(bag *bagInfo) {
	if bag == nil {
		return
	}

	t.mx.Lock()
	bag.mx.Lock()
	if t.storageBags[bag.key] == bag {
		delete(t.storageBags, bag.key)
	}
	bag.invalid = true
	closeBag := bag.references == 0
	bag.mx.Unlock()
	t.mx.Unlock()

	if closeBag {
		t.closeBag(bag)
	}
}

func (t *Transport) clearActor(site *siteInfo, expected any) {
	site.mx.Lock()
	if site.Actor != expected {
		site.mx.Unlock()
		return
	}
	if _, isBag := expected.(*bagInfo); isBag && atomic.LoadInt64(&site.inFlight) > 1 {
		site.mx.Unlock()
		return
	}
	bag := swapActorLocked(site, nil)
	site.mx.Unlock()
	t.closeBag(bag)
	if failedBag, ok := expected.(*bagInfo); ok {
		t.invalidateBag(failedBag)
	}
}

func (t *Transport) snapshotActiveSites() map[string]*siteInfo {
	t.mx.RLock()
	defer t.mx.RUnlock()

	sites := make(map[string]*siteInfo, len(t.activeSites))
	for host, info := range t.activeSites {
		sites[host] = info
	}
	return sites
}

func (t *Transport) cleaner() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.globalCtx.Done():
			return
		case <-ticker.C:
		}

		now := time.Now().Unix()
		t.cleanIdleSites(now)
		t.cleanIdleStorageBags(now)
		t.cleanIdleRLDPClients(now)
	}
}

func (t *Transport) cleanIdleSites(now int64) {
	for host, site := range t.snapshotActiveSites() {
		if atomic.LoadInt64(&site.inFlight) != 0 || atomic.LoadInt64(&site.LastUsed)+300 >= now {
			continue
		}

		if !site.mx.TryLock() {
			continue
		}
		t.mx.Lock()
		remove := t.activeSites[host] == site && atomic.LoadInt64(&site.inFlight) == 0 && atomic.LoadInt64(&site.LastUsed)+300 < now
		if remove {
			delete(t.activeSites, host)
		}
		t.mx.Unlock()
		var bag *bagInfo
		if remove {
			bag = swapActorLocked(site, nil)
		}
		site.mx.Unlock()

		t.closeBag(bag)
	}
}

func (t *Transport) cleanIdleStorageBags(now int64) {
	var expired []*bagInfo

	t.mx.Lock()
	for key, bag := range t.storageBags {
		bag.mx.Lock()
		if !bag.invalid && bag.references == 0 && bag.lastUsed+300 < now {
			bag.invalid = true
			delete(t.storageBags, key)
			expired = append(expired, bag)
		}
		bag.mx.Unlock()
	}
	t.mx.Unlock()

	for _, bag := range expired {
		t.closeBag(bag)
	}
}

func (t *Transport) cleanIdleRLDPClients(now int64) {
	t.mx.RLock()
	clients := make(map[string]*rldpInfo, len(t.rldpClients))
	for id, info := range t.rldpClients {
		clients[id] = info
	}
	t.mx.RUnlock()

	for id, info := range clients {
		if !info.mx.TryLock() {
			continue
		}
		if atomic.LoadInt64(&info.references) != 0 || atomic.LoadInt64(&info.LastUsed)+300 >= now {
			info.mx.Unlock()
			continue
		}

		t.mx.Lock()
		remove := t.rldpClients[id] == info && atomic.LoadInt64(&info.references) == 0 && atomic.LoadInt64(&info.LastUsed)+300 < now
		if remove {
			delete(t.rldpClients, id)
		}
		t.mx.Unlock()
		if !remove {
			info.mx.Unlock()
			continue
		}

		client := info.ActiveClient
		info.ActiveClient = nil
		info.mx.Unlock()
		if client != nil {
			client.Close()
		}
	}
}

func (t *Transport) connectRLDP(key ed25519.PublicKey, addr string) (RLDP, error) {
	a, err := t.gate.RegisterClient(addr, key)
	if err != nil {
		return nil, fmt.Errorf("failed to register ADNL peer %s: %w", addr, err)
	}
	r := newRLDP(a)
	r.SetOnQuery(t.getRLDPQueryHandler(r))
	return r, nil
}

func (t *Transport) getOrConnectRLDP(key ed25519.PublicKey, addr string) (*rldpInfo, error) {
	id := hex.EncodeToString(key)
	t.mx.Lock()
	if t.rldpClients == nil {
		t.rldpClients = map[string]*rldpInfo{}
	}
	info := t.rldpClients[id]
	if info == nil {
		info = &rldpInfo{ID: append(ed25519.PublicKey(nil), key...)}
		t.rldpClients[id] = info
	}
	atomic.StoreInt64(&info.LastUsed, time.Now().Unix())
	t.mx.Unlock()

	info.mx.Lock()
	defer info.mx.Unlock()
	if info.ActiveClient != nil {
		return info, nil
	}

	dial := t.connectRLDPFn
	if dial == nil {
		dial = t.connectRLDP
	}
	client, err := dial(key, addr)
	if err != nil {
		return nil, err
	}
	client.SetOnDisconnect(t.removeRLDP(info, client))
	info.ActiveClient = client
	info.Addr = addr
	return info, nil
}

func (t *Transport) lastRLDPAddress(key ed25519.PublicKey) string {
	id := hex.EncodeToString(key)
	t.mx.RLock()
	info := t.rldpClients[id]
	t.mx.RUnlock()
	if info == nil {
		return ""
	}

	info.mx.Lock()
	defer info.mx.Unlock()
	return info.Addr
}

func orderedRLDPAddresses(addresses []string, lastUsed string) []string {
	ordered := append([]string(nil), addresses...)
	for i, candidate := range ordered {
		if candidate != lastUsed || len(ordered) < 2 {
			continue
		}
		next := i + 1
		if next == len(ordered) {
			next = 0
		}
		return append(append([]string(nil), ordered[next:]...), ordered[:next]...)
	}
	return ordered
}

func rldpAddresses(records []address.Address) []string {
	addresses := make([]string, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		port := address.PortValue(record)
		if address.IsZero(record) || port <= 0 || port > 65535 {
			continue
		}
		candidate, err := address.DialString(record)
		if err != nil {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		addresses = append(addresses, candidate)
	}
	return addresses
}

func (t *Transport) removeRLDP(info *rldpInfo, rl RLDP) func() {
	return func() {
		info.mx.Lock()
		if info.ActiveClient == rl {
			info.ActiveClient = nil
		}
		info.mx.Unlock()
	}
}

func (r *rldpInfo) destroyClient(rl RLDP) bool {
	r.mx.Lock()
	if r.ActiveClient != rl {
		r.mx.Unlock()
		return false
	}
	r.ActiveClient = nil
	r.mx.Unlock()
	rl.Close()
	return true
}

func (t *Transport) createStorageBag(ctx context.Context, id []byte, host string) (*bagInfo, error) {
	torrent := storage.NewTorrent("", t.store, t.storageConnector)
	torrent.BagID = id

	if err := t.store.SetTorrent(torrent); err != nil {
		return nil, fmt.Errorf("failed to register storage bag %s, err: %w", host, err)
	}
	if err := torrent.Start(true, false, false); err != nil {
		t.store.RemoveTorrent(torrent)
		return nil, fmt.Errorf("failed to start bag %s, err: %w", host, err)
	}

	downloader, stop, err := createPersistentDownloader(ctx, t.globalCtx, func(downloaderCtx context.Context) (storage.TorrentDownloader, error) {
		return t.storageConnector.CreateDownloader(downloaderCtx, torrent)
	})
	if err != nil {
		torrent.Stop()
		t.store.RemoveTorrent(torrent)
		return nil, fmt.Errorf("failed to create downloader for storage bag of %s, err: %w", host, err)
	}

	return &bagInfo{
		torrent:    torrent,
		downloader: downloader,
		stop:       stop,
	}, nil
}

func (t *Transport) getOrCreateStorageBag(ctx context.Context, id []byte, host string) (*bagInfo, error) {
	key := hex.EncodeToString(id)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		select {
		case <-t.globalCtx.Done():
			return nil, t.globalCtx.Err()
		default:
		}

		t.mx.Lock()
		if t.storageBags == nil {
			t.storageBags = map[string]*bagInfo{}
		}
		if t.storageLoads == nil {
			t.storageLoads = map[string]*bagLoad{}
		}
		if bag := t.storageBags[key]; bag != nil {
			bag.mx.Lock()
			if !bag.invalid {
				bag.references++
				bag.lastUsed = time.Now().Unix()
				bag.mx.Unlock()
				t.mx.Unlock()
				return bag, nil
			}
			bag.mx.Unlock()
		}
		if load := t.storageLoads[key]; load != nil {
			done := load.done
			t.mx.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-t.globalCtx.Done():
				return nil, t.globalCtx.Err()
			}
		}

		load := &bagLoad{done: make(chan struct{})}
		t.storageLoads[key] = load
		t.mx.Unlock()

		create := t.createBagFn
		if create == nil {
			create = t.createStorageBag
		}
		bag, err := create(ctx, id, host)
		if err == nil && bag == nil {
			err = errors.New("storage bag is nil")
		}
		if bag != nil {
			bag.key = key
			bag.lastUsed = time.Now().Unix()
		}

		t.mx.Lock()
		if t.storageLoads[key] == load {
			delete(t.storageLoads, key)
			if err == nil {
				t.storageBags[key] = bag
			}
			close(load.done)
		}
		t.mx.Unlock()
		if err != nil {
			return nil, err
		}
	}
}

func (t *Transport) getRLDPQueryHandler(r RLDP) func(transferId []byte, query *rldp.Query) error {
	return func(transferId []byte, query *rldp.Query) error {
		switch req := query.Data.(type) {
		case GetNextPayloadPart:
			reqID := hex.EncodeToString(req.ID)

			t.mx.Lock()
			stream := t.activeRequests[reqID]
			if stream == nil {
				t.mx.Unlock()
				return fmt.Errorf("unknown request id %s", reqID)
			}
			t.mx.Unlock()

			part, err := handleGetPart(req, stream)
			if err != nil {
				return fmt.Errorf("handle part err: %w", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err = r.SendAnswer(ctx, query.MaxAnswerSize, query.Timeout, query.ID, transferId, part)
			cancel()
			if err != nil {
				return fmt.Errorf("failed to send answer: %w", err)
			}

			if part.IsLast {
				t.mx.Lock()
				delete(t.activeRequests, reqID)
				t.mx.Unlock()
				_ = stream.Data.Close()
			}

			return nil
		}
		return fmt.Errorf("unexpected query type %s", reflect.TypeOf(query.Data))
	}
}

const _MaxAllowedChunkSize = 16 << 20 // 16MB hard cap for incoming RLDP requests

func handleGetPart(req GetNextPayloadPart, stream *payloadStream) (*PayloadPart, error) {
	stream.mx.Lock()
	defer stream.mx.Unlock()

	if req.MaxChunkSize <= 0 || req.MaxChunkSize > _MaxAllowedChunkSize {
		return nil, fmt.Errorf("invalid MaxChunkSize %d for stream %s", req.MaxChunkSize, hex.EncodeToString(req.ID))
	}

	offset := int64(req.Seqno) * int64(req.MaxChunkSize)
	if offset != int64(stream.nextOffset) {
		return nil, fmt.Errorf("failed to get part for stream %s, incorrect offset %d, should be %d", hex.EncodeToString(req.ID), offset, stream.nextOffset)
	}

	var last bool
	data := make([]byte, req.MaxChunkSize)
	n, err := stream.Data.Read(data)
	if err != nil {
		if err != io.EOF {
			return nil, fmt.Errorf("failed to read chunk %d, err: %w", req.Seqno, err)
		}
		last = true
	}
	stream.nextOffset += n

	return &PayloadPart{
		Data:    data[:n],
		Trailer: nil, // TODO: trailer
		IsLast:  last,
	}, nil
}

type preparedSite struct {
	rldp   *rldpInfo
	client RLDP
	bag    *bagInfo
}

type siteResponseBody struct {
	io.ReadCloser
	release func()
}

func (b *siteResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		b.release()
	}
	return n, err
}

func (b *siteResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

func holdSiteUntilResponseClose(response *http.Response, release func()) *http.Response {
	if response.Body == nil {
		release()
		return response
	}
	response.Body = &siteResponseBody{ReadCloser: response.Body, release: release}
	return response
}

func (t *Transport) prepareSite(site *siteInfo, request *http.Request) (preparedSite, error) {
	select {
	case <-t.globalCtx.Done():
		return preparedSite{}, t.globalCtx.Err()
	default:
	}

	host := request.URL.Host
	if host == "" {
		host = request.Host
	}

	var retired *bagInfo
	site.mx.Lock()
	inFlight := atomic.LoadInt64(&site.inFlight)
	shouldRefresh := atomic.LoadInt64(&site.LastSuccess)+90 < time.Now().Unix() && inFlight <= 1
	if bag, ok := site.Actor.(*bagInfo); ok && inFlight <= 1 {
		bag.mx.Lock()
		shouldRefresh = shouldRefresh || bag.invalid
		bag.mx.Unlock()
	}
	if site.Actor == nil || shouldRefresh {
		next, err := t.resolve(request.Context(), host)
		if err != nil {
			site.mx.Unlock()
			return preparedSite{}, err
		}
		if bag, ok := next.(*bagInfo); ok {
			retired = swapRetainedBagLocked(site, bag)
		} else {
			retired = swapActorLocked(site, next)
		}
		now := time.Now().Unix()
		atomic.StoreInt64(&site.LastSuccess, now)
		atomic.StoreInt64(&site.LastUsed, now)
	}

	var prepared preparedSite
	switch actor := site.Actor.(type) {
	case *bagInfo:
		actor.mx.Lock()
		actor.lastUsed = time.Now().Unix()
		actor.mx.Unlock()
		prepared.bag = actor
	case *rldpInfo:
		actor.mx.Lock()
		client := actor.ActiveClient
		addr := actor.Addr
		lastUsed := atomic.LoadInt64(&actor.LastUsed)
		actor.mx.Unlock()

		if client != nil && lastUsed+30 < time.Now().Unix() {
			if peer, ok := client.GetADNL().(adnl.Peer); ok {
				peer.Reinit()
			}
		}

		if client == nil {
			connected, err := t.getOrConnectRLDP(actor.ID, addr)
			if err != nil {
				swapActorLocked(site, nil)
				site.mx.Unlock()
				t.closeBag(retired)
				return preparedSite{}, err
			}
			if connected != actor {
				swapActorLocked(site, connected)
				actor = connected
			}
			actor.mx.Lock()
			client = actor.ActiveClient
			actor.mx.Unlock()
		}

		if client == nil {
			swapActorLocked(site, nil)
			site.mx.Unlock()
			t.closeBag(retired)
			return preparedSite{}, fmt.Errorf("RLDP client is unavailable for %s", host)
		}
		now := time.Now().Unix()
		atomic.StoreInt64(&site.LastUsed, now)
		atomic.StoreInt64(&actor.LastUsed, now)
		prepared.rldp = actor
		prepared.client = client
	default:
		site.mx.Unlock()
		t.closeBag(retired)
		return preparedSite{}, fmt.Errorf("site actor is unavailable for %s", host)
	}
	site.mx.Unlock()
	t.closeBag(retired)
	return prepared, nil
}

func canRetryRequest(request *http.Request) bool {
	if request.Body != nil && request.Body != http.NoBody {
		return false
	}
	return request.Method == http.MethodGet || request.Method == http.MethodHead
}

func (t *Transport) RoundTrip(request *http.Request) (_ *http.Response, err error) {
	if err := request.Context().Err(); err != nil {
		return nil, err
	}

	// For multi-chain domains, the proxy sets URL.Host to the resolved .adnl
	// address while keeping Host as the original domain (e.g. "tonnet.eth").
	// Use URL.Host for routing/resolution when it differs from Host.
	host := request.URL.Host
	if host == "" {
		host = request.Host
	}

	site := t.acquireSite(host)
	releaseSite := sync.OnceFunc(func() { t.releaseSite(site) })
	defer func() {
		if err != nil {
			releaseSite()
		}
	}()

	maxAttempts := 1
	if canRetryRequest(request) {
		maxAttempts += _RoundTripMaxRetries
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			log.Info().Int("attempt", attempt+1).Str("host", host).Err(err).Msg("retrying connection")
		}

		tm := time.Now()
		prepared, prepareErr := t.prepareSite(site, request)
		err = prepareErr
		log.Info().Str("host", host).Dur("took", time.Since(tm)).Msg("prepare took")

		if err != nil {
			if requestErr := request.Context().Err(); requestErr != nil {
				return nil, requestErr
			}
			continue
		}

		if prepared.client != nil {
			var resp *http.Response
			resp, err = t.doRldpHttp(prepared.client, host, request)
			if err != nil {
				if requestErr := request.Context().Err(); requestErr != nil {
					return nil, requestErr
				}
				if prepared.rldp.destroyClient(prepared.client) {
					t.clearActor(site, prepared.rldp)
				}
				continue
			}
			atomic.StoreInt64(&site.LastSuccess, time.Now().Unix())
			return holdSiteUntilResponseClose(resp, releaseSite), nil
		}

		if prepared.bag == nil {
			err = fmt.Errorf("site actor is unavailable for %s", host)
			continue
		}
		var resp *http.Response
		resp, err = t.doTorrent(prepared.bag, request, site)
		if err != nil {
			if requestErr := request.Context().Err(); requestErr != nil {
				return nil, requestErr
			}
			t.clearActor(site, prepared.bag)
			continue
		}
		atomic.StoreInt64(&site.LastSuccess, time.Now().Unix())
		return holdSiteUntilResponseClose(resp, releaseSite), nil
	}

	if err == nil {
		err = fmt.Errorf("no response from site")
	}
	return nil, fmt.Errorf("failed to connect to site after %d attempts: %w", maxAttempts, err)
}

func (t *Transport) doTorrent(bag *bagInfo, request *http.Request, si *siteInfo) (*http.Response, error) {
	fileName := strings.TrimPrefix(request.URL.Path, "/")

	if fileName == "" {
		fileName = "index.html"
	}

	if request.Body != nil && request.Body != http.NoBody {
		defer request.Body.Close()
		if _, err := io.Copy(io.Discard, request.Body); err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	fileInfo, err := bag.torrent.GetFileOffsets(fileName)
	if err != nil {
		return &http.Response{
			Status:        "Not Found",
			StatusCode:    404,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        map[string][]string{},
			ContentLength: 0,
			Trailer:       map[string][]string{},
			Request:       request,
		}, nil
	}

	pieces := make([]byte, bag.torrent.Info.PiecesNum())

	var typ string
	if strings.Contains(fileName, ".") {
		ext := strings.Split(fileName, ".")
		typ = typeByExtension(ext[len(ext)-1])
	}
	if typ == "" {
		typ = "application/octet-stream"
	}

	fileLastIndex := fileInfo.Size
	if fileLastIndex > 0 {
		fileLastIndex -= 1
	}
	hasRange, from, to, err := t.parseRange(request, fileLastIndex)
	if err != nil {
		log.Error().Err(err).Msg("invalid range")

		return &http.Response{
			Status:        "Invalid range",
			StatusCode:    416,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        map[string][]string{},
			ContentLength: 0,
			Trailer:       map[string][]string{},
			Request:       request,
		}, nil
	}

	piecesMap := make(map[uint32]bool, fileInfo.ToPiece-fileInfo.FromPiece+1)

	var offFrom, offTo uint64 = 0, 0
	for piece := fileInfo.FromPiece; piece <= fileInfo.ToPiece; piece++ {
		sz := bag.torrent.Info.PieceSize
		if piece == fileInfo.ToPiece {
			sz = fileInfo.ToPieceOffset
		}
		if piece == fileInfo.FromPiece {
			sz -= fileInfo.FromPieceOffset
		}

		offTo += uint64(sz)
		if offTo >= from && offFrom <= to {
			pieces[piece] = 1
			piecesMap[piece] = true
		}
		offFrom = offTo
	}

	httpResp := &http.Response{
		Status:        "OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        map[string][]string{},
		ContentLength: int64((to + 1) - from),
		Trailer:       map[string][]string{},
		Request:       request,
	}

	if hasRange {
		httpResp.StatusCode = http.StatusPartialContent
		httpResp.Status = http.StatusText(http.StatusPartialContent)

		httpResp.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, to, fileInfo.Size))
		httpResp.Header.Set("Content-Length", fmt.Sprint((to+1)-from))
	} else {
		httpResp.Header.Set("Content-Length", fmt.Sprint(fileInfo.Size))
		httpResp.Header.Set("Accept-Ranges", "bytes")
	}
	httpResp.Header.Set("Content-Type", typ)

	if len(pieces) > 0 {
		fetch := storage.NewPreFetcher(request.Context(), bag.torrent, func(event storage.Event) {}, 64, pieces)
		stream := newDataStreamer()
		httpResp.Body = stream

		go func() {
			defer fetch.Stop()

			err := t.proxyOrdered(request.Context(), fileInfo, piecesMap, fetch, stream, si, bag.torrent.Info.PieceSize, from, to)
			if err != nil {
				_ = stream.Close()
				if !errors.Is(err, context.Canceled) {
					log.Error().Err(err).Msg("download ordered err")
				}
				return
			}
			stream.Finish()
		}()
	}

	return httpResp, nil
}

type requestPayload struct {
	body      io.ReadCloser
	stream    *dataStreamer
	done      chan struct{}
	closeBody sync.Once
}

func newRequestPayload(body io.ReadCloser) *requestPayload {
	payload := &requestPayload{
		body:   body,
		stream: newDataStreamer(),
		done:   make(chan struct{}),
	}
	go payload.pump()
	return payload
}

func (p *requestPayload) pump() {
	defer close(p.done)
	defer p.closeRequestBody()
	if _, err := io.Copy(p.stream, p.body); err != nil {
		_ = p.stream.Close()
		return
	}
	p.stream.Finish()
}

func (p *requestPayload) closeRequestBody() {
	p.closeBody.Do(func() {
		_ = p.body.Close()
	})
}

func (p *requestPayload) close() {
	_ = p.stream.Close()
	p.closeRequestBody()
}

func requestHasBody(request *http.Request) bool {
	return request.Body != nil && request.Body != http.NoBody
}

func buildRLDPRequest(qid []byte, host string, request *http.Request) Request {
	rldpHost := request.Host
	if rldpHost == "" {
		rldpHost = host
	}

	req := Request{
		ID:      qid,
		Method:  request.Method,
		URL:     request.URL.String(),
		Version: "HTTP/1.1",
		Headers: []Header{{Name: "Host", Value: rldpHost}},
	}

	if requestHasBody(request) {
		if request.ContentLength > 0 {
			req.Headers = append(req.Headers, Header{Name: "Content-Length", Value: strconv.FormatInt(request.ContentLength, 10)})
		} else {
			req.Headers = append(req.Headers, Header{Name: "Transfer-Encoding", Value: "chunked"})
		}
	}

	for name, values := range request.Header {
		switch http.CanonicalHeaderKey(name) {
		case "Host", "Content-Length", "Transfer-Encoding":
			continue
		}
		for _, value := range values {
			req.Headers = append(req.Headers, Header{Name: name, Value: value})
		}
	}
	return req
}

func (t *Transport) doRldpHttp(client RLDP, host string, request *http.Request) (*http.Response, error) {
	qid := make([]byte, 32)
	_, err := rand.Read(qid)
	if err != nil {
		return nil, err
	}

	req := buildRLDPRequest(qid, host, request)

	if requestHasBody(request) {
		payload := newRequestPayload(request.Body)
		stream := &payloadStream{Data: payload.stream, ValidTill: time.Now().Add(15 * time.Second)}
		requestID := hex.EncodeToString(qid)
		t.mx.Lock()
		t.activeRequests[requestID] = stream
		t.mx.Unlock()
		defer func() {
			t.mx.Lock()
			if t.activeRequests[requestID] == stream {
				delete(t.activeRequests, requestID)
			}
			t.mx.Unlock()
			payload.close()
		}()
	}

	var res Response
	err = client.DoQuery(request.Context(), _RLDPMaxAnswerSize, req, &res)
	if err != nil {
		return nil, fmt.Errorf("failed to query http over rldp: %w", err)
	}

	httpResp := &http.Response{
		Status:        res.Reason,
		StatusCode:    int(res.StatusCode),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        map[string][]string{},
		ContentLength: -1,
		Trailer:       map[string][]string{},
		Request:       request,
	}

	for _, header := range res.Headers {
		if isBlockedResponseHeader(header.Name) {
			continue
		}
		httpResp.Header.Add(header.Name, header.Value)
	}

	if contentLength := httpResp.Header.Get("Content-Length"); contentLength != "" {
		httpResp.ContentLength, err = strconv.ParseInt(contentLength, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse content length: %w", err)
		}
	}

	withPayload := !res.NoPayload && (httpResp.StatusCode < 300 || httpResp.StatusCode >= 400)

	dr := newDataStreamer()
	httpResp.Body = dr

	if withPayload {
		if httpResp.ContentLength > 0 && httpResp.ContentLength < (1<<22) {
			dr.buf = make([]byte, 0, httpResp.ContentLength)
		}

		go func() {
			if err := fetchRLDPPayload(request.Context(), client, qid, httpResp, dr, _RLDPContinuationDelay); err != nil {
				_ = dr.Close()
				log.Warn().Err(err).Str("host", host).Msg("RLDP payload stream failed")
			}
		}()
	} else {
		dr.Finish()
	}

	return httpResp, nil
}

func fetchRLDPPayload(ctx context.Context, client RLDP, qid []byte, httpResp *http.Response, dr *dataStreamer, continuationDelay time.Duration) error {
	for seqno := int32(0); ; seqno++ {
		if seqno > 0 && continuationDelay > 0 {
			timer := time.NewTimer(continuationDelay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}

		var part PayloadPart
		if err := client.DoQuery(ctx, _RLDPMaxAnswerSize*1000, GetNextPayloadPart{
			ID:           qid,
			Seqno:        seqno,
			MaxChunkSize: _ChunkSize * 100,
		}, &part); err != nil {
			return fmt.Errorf("failed to fetch payload continuation %d: %w", seqno, err)
		}

		for _, tr := range part.Trailer {
			httpResp.Trailer[tr.Name] = []string{tr.Value}
		}

		if _, err := dr.Write(part.Data); err != nil {
			return err
		}
		if part.IsLast {
			dr.Finish()
			return nil
		}
	}
}

func (t *Transport) resolve(ctx context.Context, host string) (_ any, err error) {
	var id []byte
	var inStorage bool
	if strings.HasSuffix(host, ".adnl") {
		id, err = ParseADNLAddress(host[:len(host)-5])
		if err != nil {
			return nil, fmt.Errorf("failed to parse adnl address %s, err: %w", host, err)
		}
	} else if strings.HasSuffix(host, ".bag") {
		id, err = hex.DecodeString(host[:len(host)-4])
		if err != nil {
			return nil, fmt.Errorf("failed to parse bag id %s, err: %w", host, err)
		}
		inStorage = true
	} else {
		tm := time.Now()
		lookupCtx, stopLookup := context.WithCancel(ctx)
		ch := make(chan *dns.Domain, 3)
		const _MaxResolveRetries = 5
		for i := 0; i < 3; i++ { // do parallel lookup on diff nodes to speedup
			go func(i int) {
				for attempt := 0; attempt < _MaxResolveRetries; attempt++ {
					// each new thread has bigger timeout, to cover users with high ping
					resolveCtx, cancel := context.WithTimeout(lookupCtx, time.Duration((i+1)*2)*time.Second)
					domain, err := t.resolver.Resolve(t.pool.StickyContext(resolveCtx), host)
					cancel()
					if err != nil {
						if lookupCtx.Err() != nil {
							return
						}

						if errors.Is(err, dns.ErrNoSuchRecord) {
							ch <- nil
							return
						}
						log.Error().Err(err).Msg("domain resolve error")
						continue
					}

					ch <- domain
					return
				}
			}(i)
		}

		var domain *dns.Domain
		select {
		case domain = <-ch:
			stopLookup()
			if domain == nil {
				return nil, fmt.Errorf("domain %s resolve err: %w", host, dns.ErrNoSuchRecord)
			}
		case <-lookupCtx.Done():
			stopLookup()
			return nil, fmt.Errorf("failed to resolve domain %s in ton dns", host)
		}
		log.Info().Str("domain", host).Dur("duration", time.Since(tm)).Msg("resolve domain took")

		id, inStorage = domain.GetSiteRecord()
	}

	if inStorage {
		log.Info().Str("bag_id", hex.EncodeToString(id)).Str("host", host).Msg("searching for bag id")
		bag, err := t.getOrCreateStorageBag(ctx, id, host)
		if err != nil {
			return nil, err
		}
		log.Info().Str("bag_id", hex.EncodeToString(id)).Str("host", host).Msg("bag found")
		return bag, nil
	}

	log.Info().Str("host", host).Str("node", hex.EncodeToString(id)).Msg("resolving ton site address")

	dhtCtx, dhtCancel := context.WithTimeout(ctx, _DHTFindTimeout)
	defer dhtCancel()

	addresses, pubKey, err := t.dht.FindAddresses(dhtCtx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to find address of %s (%s) in DHT, err: %w", host, hex.EncodeToString(id), err)
	}

	if addresses == nil || len(addresses.Addresses) == 0 {
		return nil, fmt.Errorf("failed to find address of %s (%s) in DHT, no addresses in record", host, hex.EncodeToString(id))
	}

	log.Info().Str("host", host).Str("node", hex.EncodeToString(id)).Msg("server address resolved")

	candidates := orderedRLDPAddresses(rldpAddresses(addresses.Addresses), t.lastRLDPAddress(pubKey))
	if len(candidates) == 0 {
		return nil, fmt.Errorf("failed to connect to host %s, DHT record has no valid addresses", host)
	}

	var info *rldpInfo
	var addr string
	var triedAddresses []string
	for _, candidateAddr := range candidates {
		log.Info().Str("host", host).Str("node", hex.EncodeToString(id)).Str("address", candidateAddr).Msg("registering TON site peer")
		candidate, connectErr := t.getOrConnectRLDP(pubKey, candidateAddr)
		if connectErr != nil {
			log.Error().Err(connectErr).Msg("RLDP connection failed")
			log.Debug().Str("host", host).Str("node", hex.EncodeToString(id)).Str("address", candidateAddr).Msg("RLDP connection failed details")
			triedAddresses = append(triedAddresses, candidateAddr)
			err = connectErr
			continue
		}
		info = candidate
		info.mx.Lock()
		addr = info.Addr
		info.mx.Unlock()
		break
	}
	if info == nil {
		return nil, fmt.Errorf("failed to connect to rldp servers %s of host %s, err: %w", triedAddresses, host, err)
	}

	log.Info().Str("host", host).Str("node", hex.EncodeToString(id)).Str("address", addr).Msg("RLDP peer registered")
	return info, nil
}

func (t *Transport) proxyOrdered(ctx context.Context, file *storage.FileInfo,
	piecesMap map[uint32]bool, fetch *storage.PreFetcher, stream *dataStreamer, si *siteInfo,
	pieceSz uint32, from, to uint64) error {
	var err error
	var currentPieceId uint32
	var currentPiece []byte

	notEmptyFile := file.FromPiece != file.ToPiece || file.FromPieceOffset != file.ToPieceOffset
	if notEmptyFile {
		var toOff uint64
		var wasFirst bool
		for piece := file.FromPiece; piece <= file.ToPiece; piece++ {
			sz := pieceSz
			if piece == file.ToPiece {
				sz = file.ToPieceOffset
			}
			if piece == file.FromPiece {
				sz -= file.FromPieceOffset
			}
			toOff += uint64(sz)

			if !piecesMap[piece] {
				continue
			}

			if piece != currentPieceId || currentPiece == nil {
				if currentPiece != nil {
					fetch.Free(currentPieceId)
				}

				atomic.StoreInt64(&si.LastUsed, time.Now().Unix())

				currentPiece, _, err = fetch.WaitGet(ctx, piece)
				if err != nil {
					return fmt.Errorf("failed to download piece %d: %w", piece, err)
				}

				currentPieceId = piece
			}
			part := currentPiece
			if piece == file.ToPiece {
				part = part[:file.ToPieceOffset]
			}
			if piece == file.FromPiece {
				part = part[file.FromPieceOffset:]
			}

			toOffIdx := toOff - 1
			if toOffIdx > to {
				diff := toOffIdx - to
				part = part[:len(part)-int(diff)]
			}

			fromOff := toOff - uint64(sz)
			if !wasFirst && from > fromOff {
				part = part[from-fromOff:]
			}
			wasFirst = true

			_, err = stream.Write(part)
			if err != nil {
				return fmt.Errorf("failed to write piece %d: %w", piece, err)
			}
		}
	}
	if err != nil {
		return err
	}

	if currentPiece != nil {
		fetch.Free(currentPieceId)
	}
	return nil
}

func (t *Transport) parseRange(request *http.Request, max uint64) (hasRange bool, from uint64, to uint64, err error) {
	rng := request.Header.Get("Range")
	if len(rng) > 6 && strings.HasPrefix(rng, "bytes=") {
		ranges := strings.SplitN(rng[6:], ",", 2)
		if len(ranges) > 1 {
			return false, 0, 0, fmt.Errorf("multiple ranges not supported")
		}

		rngArr := strings.SplitN(ranges[0], "-", 2)
		if len(rngArr) != 2 {
			return false, 0, 0, fmt.Errorf("invalid range format")
		}

		if rngArr[0] != "" {
			from, err = strconv.ParseUint(rngArr[0], 10, 64)
			if err != nil {
				return false, 0, 0, err
			}
			if from > max {
				return false, 0, 0, fmt.Errorf("invalid from range, over max")
			}
		}

		if rngArr[1] != "" {
			to, err = strconv.ParseUint(rngArr[1], 10, 64)
			if err != nil {
				return false, 0, 0, err
			}

			if to > max {
				return false, 0, 0, fmt.Errorf("invalid to range, over max")
			}
		} else {
			to = max
		}

		if from > to {
			return false, 0, 0, fmt.Errorf("invalid range, from > to (%d > %d)", from, to)
		}
		return true, from, to, nil
	}
	return false, 0, max, nil
}
