package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/adnl/rldp"
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
const _MaxPayloadChunkSize = _ChunkSize * 100
const _RLDPMaxAnswerSize = 2*_ChunkSize + 1024
const _RLDP2Capability int64 = 1
const _QUICCapability int64 = 2
const _QUICRetryDelay = 30 * time.Second
const _TransportConnectTimeout = 3 * time.Second
const _QUICIdleTimeout = 5 * time.Minute

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
	torrent    *storage.Torrent
	downloader storage.TorrentDownloader
}

var newRLDP = func(a ADNL) RLDP {
	return rldp.NewClientV2(a)
}

type siteInfo struct {
	Actor any

	LastUsed     int64
	LastSuccess  int64
	QUICLastUsed int64
	quicInFlight int64
	mx           sync.RWMutex
}

type rldpInfo struct {
	ActiveClient         RLDP
	quicClient           *quicClient
	quicUse              *quicReference
	capabilities         int64
	quicAddr             string
	retryQUICAt          time.Time
	capabilitiesReceived bool
	inProgress           bool
	quicCancel           context.CancelFunc
	quicGeneration       uint64
	quicWake             chan struct{}

	ID   ed25519.PublicKey
	Addr string
}

type Transport struct {
	dht              DHT
	resolver         Resolver
	storageConnector storage.NetConnector
	store            *VirtualStorage
	gate             *adnl.Gateway
	quicGate         *quic.Gateway
	quicMx           sync.Mutex
	quicPeers        map[string]*quicOwner
	quicIdleTimeout  time.Duration
	dialQUIC         func(context.Context, ed25519.PublicKey, string) (*quic.Peer, error)

	activeSites map[string]*siteInfo

	activeRequests map[string]*payloadStream
	globalCtx      context.Context
	stop           func()
	mx             sync.RWMutex
}

func NewTransport(gate *adnl.Gateway, key ed25519.PrivateKey, dht DHT, resolver Resolver, storeConn storage.NetConnector, store *VirtualStorage, enableQUIC bool) *Transport {
	t := &Transport{
		gate:             gate,
		dht:              dht,
		resolver:         resolver,
		storageConnector: storeConn,
		store:            store,
		activeRequests:   map[string]*payloadStream{},
		activeSites:      map[string]*siteInfo{},
		quicPeers:        make(map[string]*quicOwner),
		quicIdleTimeout:  _QUICIdleTimeout,
	}
	t.globalCtx, t.stop = context.WithCancel(context.Background())
	if enableQUIC {
		quicGate, err := quic.NewGateway(key)
		if err != nil {
			log.Warn().Err(err).Msg("failed to init QUIC gateway, continuing with RLDP")
		} else {
			t.quicGate = quicGate
			t.dialQUIC = quicGate.DialDefault
			quicGate.SetConnectionHandler(func(peer *quic.Peer) error {
				peer.SetQueryHandler(t.handleQUICQuery)
				return nil
			})
		}
	}
	go t.cleaner()
	return t
}

func (t *Transport) Stop() {
	t.stop()
	if t.quicGate != nil {
		_ = t.quicGate.Close()
	}
}

func (t *Transport) cleaner() {
	for {
		select {
		case <-t.globalCtx.Done():
			return
		case <-time.After(3 * time.Second):
		}

		t.cleanIdle(time.Now())
	}
}

func (t *Transport) cleanIdle(now time.Time) {
	t.mx.RLock()
	idle := t.quicIdleTimeout
	sites := make(map[string]*siteInfo, len(t.activeSites))
	for host, site := range t.activeSites {
		sites[host] = site
	}
	t.mx.RUnlock()
	for host, site := range sites {
		if !site.mx.TryLock() {
			continue
		}
		var retired *quicReference
		switch act := site.Actor.(type) {
		case *bagInfo:
			if atomic.LoadInt64(&site.LastUsed)+300 < now.Unix() {
				t.mx.Lock()
				if t.activeSites[host] == site {
					delete(t.activeSites, host)
				}
				t.mx.Unlock()
				act.downloader.Close()
				act.torrent.Stop()
				log.Debug().Hex("bag_id", act.torrent.BagID).Msg("stopped unused bag")
			}
		case *rldpInfo:
			if atomic.LoadInt64(&site.quicInFlight) == 0 && now.Sub(time.Unix(0, atomic.LoadInt64(&site.QUICLastUsed))) > idle {
				if act.inProgress || act.quicCancel != nil {
					act.stopQUICWorker()
				}
				retired = act.quicUse
				act.quicClient = nil
				act.quicUse = nil
				act.retryQUICAt = time.Time{}
			}
		}
		site.mx.Unlock()
		if retired != nil {
			t.releaseQUIC(retired)
		}
	}
}

func (t *Transport) connectRLDP(key ed25519.PublicKey, addr, host string) (RLDP, error) {
	a, err := t.gate.RegisterClient(addr, key)
	if err != nil {
		return nil, fmt.Errorf("failed to init adnl for rldp connection %s, err: %w", addr, err)
	}
	r := newRLDP(a)
	r.SetOnQuery(t.getRLDPQueryHandler(r))
	r.SetOnDisconnect(t.removeRLDP(r, host))
	return r, nil
}

// Called under site.mx, after this request has selected its transport.
func (t *Transport) startQUICWorker(site *siteInfo, info *rldpInfo) {
	if t.quicGate == nil || info.inProgress || info.quicAddr == "" ||
		(info.capabilitiesReceived && info.capabilities&_QUICCapability == 0) {
		return
	}
	ctx, cancel := context.WithCancel(t.globalCtx)
	// A canceled generation must not consume its successor's notifications.
	info.quicWake = make(chan struct{}, 1)
	wake := info.quicWake
	if info.quicUse != nil {
		t.quicMx.Lock()
		info.quicUse.client.owner.users[info.quicUse] = wake
		t.quicMx.Unlock()
	}
	info.quicCancel = cancel
	info.inProgress = true
	info.quicGeneration++
	generation := info.quicGeneration
	go func() { defer cancel(); t.watchQUIC(ctx, site, info, generation, wake) }()
}

func (r *rldpInfo) stopQUICWorker() {
	if !r.inProgress && r.quicCancel == nil {
		return
	}
	if r.quicCancel != nil {
		r.quicCancel()
		r.quicCancel = nil
	}
	r.quicGeneration++
	r.inProgress = false
}

func notifyQUIC(wake chan struct{}) {
	select {
	case wake <- struct{}{}:
	default:
	}
}

func waitQUIC(ctx context.Context, wake <-chan struct{}, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-wake:
		return true
	case <-timer.C:
		return true
	}
}

func (t *Transport) watchQUIC(ctx context.Context, site *siteInfo, info *rldpInfo, generation uint64, wake chan struct{}) {
	current := func() bool { return site.Actor == info && info.quicGeneration == generation && ctx.Err() == nil }
	defer func() {
		site.mx.Lock()
		if info.quicGeneration == generation {
			info.inProgress = false
			info.quicCancel = nil
		}
		site.mx.Unlock()
	}()
	for {
		site.mx.Lock()
		if !current() {
			site.mx.Unlock()
			return
		}
		if info.quicClient != nil {
			if !info.quicClient.failed.Load() {
				site.mx.Unlock()
				select {
				case <-ctx.Done():
					return
				case <-wake:
				}
				continue
			}
			retired := info.quicUse
			info.quicClient = nil
			info.quicUse = nil
			info.retryQUICAt = time.Now().Add(_QUICRetryDelay)
			site.mx.Unlock()
			t.releaseQUIC(retired)
			continue
		}
		if delay := time.Until(info.retryQUICAt); delay > 0 {
			site.mx.Unlock()
			if !waitQUIC(ctx, wake, delay) {
				return
			}
			continue
		}
		probe := !info.capabilitiesReceived
		if !probe && info.capabilities&_QUICCapability == 0 {
			site.mx.Unlock()
			return
		}
		if info.ActiveClient == nil {
			site.mx.Unlock()
			if !waitQUIC(ctx, wake, _QUICRetryDelay) {
				return
			}
			continue
		}
		peer := info.ActiveClient.GetADNL().(adnl.Peer)
		info.retryQUICAt = time.Now().Add(_QUICRetryDelay)
		site.mx.Unlock()

		attempt, cancel := context.WithTimeout(ctx, _TransportConnectTimeout)
		if probe {
			var capabilities Capabilities
			err := peer.Query(attempt, GetCapabilities{Capabilities: _RLDP2Capability | _QUICCapability}, &capabilities)
			cancel()
			site.mx.Lock()
			if !current() {
				site.mx.Unlock()
				return
			}
			if err == nil {
				info.capabilities = capabilities.Value
				info.capabilitiesReceived = true
				info.retryQUICAt = time.Time{}
			}
			site.mx.Unlock()
			if err != nil {
				log.Debug().Err(err).Msg("background capability probe failed, keeping RLDP2")
			}
			continue
		}
		use, err := t.acquireQUIC(attempt, info, wake)
		cancel()
		site.mx.Lock()
		if !current() {
			site.mx.Unlock()
			if use != nil {
				t.releaseQUIC(use)
			}
			return
		}
		if err != nil {
			info.retryQUICAt = time.Now().Add(_QUICRetryDelay)
			site.mx.Unlock()
			log.Debug().Err(err).Str("address", info.quicAddr).Msg("failed to dial QUIC, using RLDP")
			continue
		}
		info.quicClient = use.client
		info.quicUse = use
		info.retryQUICAt = time.Time{}
		site.mx.Unlock()
		log.Info().Str("address", info.quicAddr).Msg("using QUIC for ton site")
	}
}

// Re-resolution preserves the capability cache only for the same peer endpoint.
// Release the returned old client reference after releasing site.mx.
func (t *Transport) reconcileQUIC(site *siteInfo, old *rldpInfo) *quicReference {
	next, _ := site.Actor.(*rldpInfo)
	if old == nil || old == next {
		return nil
	}
	old.stopQUICWorker()
	if next != nil && bytes.Equal(old.ID, next.ID) && old.Addr == next.Addr && old.quicAddr == next.quicAddr {
		next.quicClient = old.quicClient
		next.quicUse = old.quicUse
		old.quicUse = nil
		next.capabilities = old.capabilities
		next.capabilitiesReceived = old.capabilitiesReceived
		next.retryQUICAt = old.retryQUICAt
		old.quicClient = nil
		return nil
	}
	if old.quicClient != nil {
		use := old.quicUse
		old.quicClient = nil
		old.quicUse = nil
		return use
	}
	return nil
}

// quicOwner is guarded by Transport.quicMx. A busy owner is dialing or closing.
// Keeping it registered until Close finishes prevents DialDefault reusing a peer
// that another site has just released.
type quicOwner struct {
	key    string
	client *quicClient
	users  map[*quicReference]chan struct{}
	busy   chan struct{}
}

// Each acquisition has its own reference, including overlapping worker
// generations for one site. Releasing a canceled generation cannot detach its successor.
type quicReference struct{ client *quicClient }

func (t *Transport) acquireQUIC(ctx context.Context, info *rldpInfo, wake chan struct{}) (*quicReference, error) {
	key := string(info.ID)
	for {
		t.quicMx.Lock()
		owner := t.quicPeers[key]
		if owner != nil && owner.busy != nil {
			done := owner.busy
			t.quicMx.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if owner != nil {
			if owner.client.failed.Load() {
				t.quicMx.Unlock()
				return nil, quic.ErrPeerClosed
			}
			use := &quicReference{client: owner.client}
			owner.users[use] = wake
			t.quicMx.Unlock()
			return use, nil
		}
		owner = &quicOwner{key: key, users: make(map[*quicReference]chan struct{}), busy: make(chan struct{})}
		t.quicPeers[key] = owner
		t.quicMx.Unlock()

		peer, err := t.dialQUIC(ctx, info.ID, info.quicAddr)
		var client *quicClient
		var use *quicReference
		if err == nil {
			client = &quicClient{peer: peer, transport: t, owner: owner}
			peer.SetDisconnectHandler(func(*quic.Peer) { client.markFailed() })
		}
		t.quicMx.Lock()
		if err != nil {
			delete(t.quicPeers, key)
		} else {
			owner.client = client
			use = &quicReference{client: client}
			owner.users[use] = wake
		}
		close(owner.busy)
		owner.busy = nil
		t.quicMx.Unlock()
		return use, err
	}
}

func (t *Transport) releaseQUIC(use *quicReference) {
	client := use.client
	t.quicMx.Lock()
	delete(client.owner.users, use)
	t.quicMx.Unlock()
	t.closeUnusedQUIC(client)
}

func (t *Transport) closeUnusedQUIC(client *quicClient) {
	t.quicMx.Lock()
	owner := client.owner
	if t.quicPeers[owner.key] != owner || len(owner.users) != 0 || client.inFlight.Load() != 0 || owner.busy != nil {
		t.quicMx.Unlock()
		return
	}
	owner.busy = make(chan struct{})
	t.quicMx.Unlock()
	_ = client.peer.Close()
	t.quicMx.Lock()
	if t.quicPeers[owner.key] == owner {
		delete(t.quicPeers, owner.key)
	}
	close(owner.busy)
	owner.busy = nil
	t.quicMx.Unlock()
}

func (t *Transport) removeRLDP(rl RLDP, host string) func() {
	return func() {
		t.mx.RLock()
		r := t.activeSites[host]
		t.mx.RUnlock()

		if r == nil {
			return
		}

		r.mx.Lock()
		defer r.mx.Unlock()

		if act, ok := r.Actor.(*rldpInfo); ok {
			act.destroyClient(rl)
		}
	}
}

func (r *rldpInfo) destroyClient(rl RLDP) {
	rl.Close()

	if r.ActiveClient == rl {
		r.ActiveClient = nil
	}
}

func (t *Transport) getRLDPQueryHandler(r RLDP) func(transferId []byte, query *rldp.Query) error {
	return func(transferId []byte, query *rldp.Query) error {
		switch req := query.Data.(type) {
		case GetNextPayloadPart:
			return t.handlePayloadQuery(req, func(part *PayloadPart) error {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				return r.SendAnswer(ctx, query.MaxAnswerSize, query.Timeout, query.ID, transferId, part)
			})
		}
		return fmt.Errorf("unexpected query type %s", reflect.TypeOf(query.Data))
	}
}

func (t *Transport) handlePayloadQuery(req GetNextPayloadPart, answer func(*PayloadPart) error) error {
	t.mx.RLock()
	stream := t.activeRequests[hex.EncodeToString(req.ID)]
	t.mx.RUnlock()
	if stream == nil {
		return fmt.Errorf("unknown request id %s", hex.EncodeToString(req.ID))
	}

	part, err := handleGetPart(req, stream)
	if err != nil {
		return fmt.Errorf("handle part err: %w", err)
	}
	if stream.touch != nil {
		stream.touch()
	}
	if err = answer(part); err != nil {
		return fmt.Errorf("failed to send answer: %w", err)
	}
	if part.IsLast {
		t.mx.Lock()
		delete(t.activeRequests, hex.EncodeToString(req.ID))
		t.mx.Unlock()
		_ = stream.Data.Close()
	}
	return nil
}

func (t *Transport) handleQUICQuery(_ context.Context, data []byte) ([]byte, error) {
	var req GetNextPayloadPart
	if err := parseQUICHTTP(data, &req); err != nil {
		return nil, err
	}
	var answer []byte
	err := t.handlePayloadQuery(req, func(part *PayloadPart) (err error) {
		answer, err = tl.Serialize(part, true)
		return err
	})
	return answer, err
}

func handleGetPart(req GetNextPayloadPart, stream *payloadStream) (*PayloadPart, error) {
	if req.Seqno < 0 || req.MaxChunkSize <= 0 || req.MaxChunkSize > _MaxPayloadChunkSize {
		return nil, fmt.Errorf("invalid payload part bounds")
	}
	stream.mx.Lock()
	defer stream.mx.Unlock()

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

func (s *siteInfo) prepare(t *Transport, request *http.Request) (err error) {
	select {
	case <-t.globalCtx.Done():
		return t.globalCtx.Err()
	default:
	}

	host := request.Host
	if host == "" {
		host = request.URL.Host
	}

	if s.Actor == nil || atomic.LoadInt64(&s.LastSuccess)+90 < time.Now().Unix() {
		s.Actor, err = t.resolve(request.Context(), host)
		if err != nil {
			return err
		}
		// update success after resolve to not re-resolve too soon
		atomic.StoreInt64(&s.LastSuccess, time.Now().Unix())
		atomic.StoreInt64(&s.LastUsed, time.Now().Unix())
	}

	switch act := s.Actor.(type) {
	case *bagInfo:
		atomic.StoreInt64(&s.LastUsed, time.Now().Unix())
	case *rldpInfo:
		if act.ActiveClient != nil && atomic.LoadInt64(&s.LastUsed)+30 < time.Now().Unix() {
			act.ActiveClient.GetADNL().(adnl.Peer).Reinit()
			atomic.StoreInt64(&s.LastUsed, time.Now().Unix())
		}

		if act.ActiveClient == nil {
			act.ActiveClient, err = t.connectRLDP(act.ID, act.Addr, host)
			if err != nil {
				// resolve again
				s.Actor = nil
				return s.prepare(t, request)
			}
			notifyQUIC(act.quicWake)
			atomic.StoreInt64(&s.LastUsed, time.Now().Unix())
		}
	}
	return nil
}

func (t *Transport) RoundTrip(request *http.Request) (_ *http.Response, err error) {
	host := request.Host
	if host == "" {
		host = request.URL.Host
	}

	t.mx.Lock()
	site := t.activeSites[host]
	if site == nil {
		site = &siteInfo{
			LastUsed: time.Now().Unix(),
		}
		t.activeSites[host] = site
	}
	t.mx.Unlock()

	var rldpClient httpClient
	var flight *quicRequest
	var torrent *bagInfo

	tm := time.Now()
	site.mx.Lock()
	previousActor := site.Actor
	previous, _ := previousActor.(*rldpInfo)
	err = site.prepare(t, request)
	log.Info().Str("host", host).Dur("took", time.Since(tm)).Msg("prepare took")

	if err != nil {
		// A failed lookup has not established a different peer endpoint.
		site.Actor = previousActor
		site.mx.Unlock()
		return nil, fmt.Errorf("failed to connect to site: %w", err)
	}
	retired := t.reconcileQUIC(site, previous)

	switch act := site.Actor.(type) {
	case *rldpInfo:
		rldpClient = act.ActiveClient
		if act.quicClient != nil && !act.quicClient.failed.Load() {
			flight = act.quicClient.beginRequest(site)
			rldpClient = flight
		}
		t.startQUICWorker(site, act)
	case *bagInfo:
		torrent = act
	}
	atomic.StoreInt64(&site.QUICLastUsed, time.Now().UnixNano())
	site.mx.Unlock()
	if retired != nil {
		t.releaseQUIC(retired)
	}

	if rldpClient != nil {
		resp, err := t.doRldpHttp(rldpClient, host, request)
		if flight != nil {
			if err != nil {
				flight.release()
			} else {
				resp.Body = &quicResponseBody{ReadCloser: resp.Body, flight: flight}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed to request rldp-http site: %w", err)
		}
		atomic.StoreInt64(&site.LastSuccess, time.Now().Unix())
		return resp, nil
	}

	resp, err := t.doTorrent(torrent, request, site)
	if err != nil {
		return nil, fmt.Errorf("failed to request file from storage: %w", err)
	}
	atomic.StoreInt64(&site.LastSuccess, time.Now().Unix())
	return resp, nil
}

func (t *Transport) doTorrent(bag *bagInfo, request *http.Request, si *siteInfo) (*http.Response, error) {
	fileName := request.URL.Path
	if strings.HasPrefix(fileName, "/") {
		fileName = fileName[1:]
	}

	if fileName == "" {
		fileName = "index.html"
	}

	if request.Body != nil {
		tmp := make([]byte, 4096)
		for { // discard body
			_, err := request.Body.Read(tmp)
			if err != nil {
				if err == io.EOF {
					break
				}
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}
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

func (t *Transport) doRldpHttp(client httpClient, host string, request *http.Request) (*http.Response, error) {
	flight, _ := client.(*quicRequest)
	qid := make([]byte, 32)
	_, err := rand.Read(qid)
	if err != nil {
		return nil, err
	}

	req := Request{
		ID:      qid,
		Method:  request.Method,
		URL:     request.URL.String(),
		Version: "HTTP/1.1",
		Headers: []Header{
			{
				Name:  "Host",
				Value: host,
			},
		},
	}

	if request.ContentLength > 0 {
		req.Headers = append(req.Headers, Header{
			Name:  "Content-Length",
			Value: fmt.Sprint(request.ContentLength),
		})
	}

	for k, v := range request.Header {
		for _, hdr := range v {
			req.Headers = append(req.Headers, Header{
				Name:  k,
				Value: hdr,
			})
		}
	}

	if request.Body != nil {
		stream := newDataStreamer()

		// Uploads and response bodies retain the logical QUIC request independently.
		if flight != nil {
			flight.retain()
		}
		// chunked stream reader
		go func() {
			if flight != nil {
				defer flight.release()
			}
			defer request.Body.Close()

			for {
				buf := make([]byte, 4096)
				n, err := request.Body.Read(buf)
				if flight != nil {
					flight.touch()
				}
				if err != nil {
					if errors.Is(err, io.EOF) {
						_, err = stream.Write(buf[:n])
						if err == nil {
							stream.Finish()
							break
						}
					}
					_ = stream.Close()
					break
				}

				_, err = stream.Write(buf[:n])
				if err != nil {
					_ = stream.Close()
					break
				}
			}
		}()

		t.mx.Lock()
		var touch func()
		if flight != nil {
			touch = flight.touch
		}
		t.activeRequests[hex.EncodeToString(qid)] = &payloadStream{
			Data:      stream,
			ValidTill: time.Now().Add(15 * time.Second),
			touch:     touch,
		}
		t.mx.Unlock()

		defer func() {
			t.mx.Lock()
			delete(t.activeRequests, hex.EncodeToString(qid))
			t.mx.Unlock()
			_ = stream.Close()
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
		httpResp.Header.Add(header.Name, header.Value)
	}

	if ln, ok := request.Header["Content-Length"]; ok && len(ln) > 0 {
		httpResp.ContentLength, err = strconv.ParseInt(ln[0], 10, 64)
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

		if flight != nil {
			flight.retain()
		}
		go func() {
			if flight != nil {
				defer flight.release()
			}
			seqno := int32(0)
			for withPayload {
				var part PayloadPart
				err := client.DoQuery(request.Context(), _RLDPMaxAnswerSize*1000, GetNextPayloadPart{
					ID:           qid,
					Seqno:        seqno,
					MaxChunkSize: _MaxPayloadChunkSize,
				}, &part)
				if err != nil {
					_ = dr.Close()
					return
				}

				for _, tr := range part.Trailer {
					httpResp.Trailer[tr.Name] = []string{tr.Value}
				}

				withPayload = !part.IsLast
				_, err = dr.Write(part.Data)
				if err != nil {
					_ = dr.Close()
					return
				}

				if part.IsLast {
					dr.Finish()
				}

				seqno++
			}
		}()
	} else {
		dr.Finish()
	}

	return httpResp, nil
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
		for i := 0; i < 3; i++ { // do parallel lookup on diff nodes to speedup
			go func(i int) {
				for {
					// each new thread has bigger timeout, to cover users with high ping
					resolveCtx, cancel := context.WithTimeout(lookupCtx, time.Duration((i+1)*2)*time.Second)
					domain, err := t.resolver.Resolve(resolveCtx, host)
					cancel()
					if err != nil {
						if lookupCtx.Err() != nil {
							return
						}

						if errors.Is(err, dns.ErrNoSuchRecord) {
							ch <- nil
							return
						}
						log.Error().Err(err).Str("domain", host).Msg("resolve error")
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

		torrent := storage.NewTorrent("", t.store, t.storageConnector)
		torrent.BagID = id

		_ = t.store.SetTorrent(torrent)

		if err = torrent.Start(true, false, false); err != nil {
			return nil, fmt.Errorf("failed to start bag %s, err: %w", host, err)
		}
		log.Info().Str("bag_id", hex.EncodeToString(id)).Str("host", host).Msg("starting for bag id")

		downloader, err := t.storageConnector.CreateDownloader(t.globalCtx, torrent)
		if err != nil {
			return nil, fmt.Errorf("failed to create downloader for storage bag of %s, err: %w", host, err)
		}

		log.Info().Str("bag_id", hex.EncodeToString(id)).Str("host", host).Msg("bag found")
		return &bagInfo{
			torrent:    torrent,
			downloader: downloader,
		}, nil
	}

	log.Info().Str("host", host).Str("node", hex.EncodeToString(id)).Msg("resolving ton site address")

	addresses, pubKey, err := t.dht.FindAddresses(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to find address of %s (%s) in DHT, err: %w", host, hex.EncodeToString(id), err)
	}

	if len(addresses.Addresses) == 0 {
		return nil, fmt.Errorf("failed to find address of %s (%s) in DHT,no addresses in record", host, hex.EncodeToString(id))
	}

	log.Info().Str("host", host).Str("node", hex.EncodeToString(id)).Msg("server address resolved")

	var addr string
	var client RLDP
	var triedAddresses []string
	err = fmt.Errorf("no UDP addresses in DHT record")
	for _, v := range addresses.Addresses {
		switch v := v.(type) {
		case *address.UDP:
			addr = fmt.Sprintf("%s:%d", v.IP.String(), v.Port)
		default:
			continue
		}

		log.Info().Str("host", host).Str("node", hex.EncodeToString(id)).Str("address", addr).Msg("connecting to ton site")

		// find working rldp node addr
		client, err = t.connectRLDP(pubKey, addr, host)
		if err != nil {
			log.Error().Err(err).Str("host", host).Str("node", hex.EncodeToString(id)).Str("address", addr).Msg("connection failed")

			triedAddresses = append(triedAddresses, addr)
			continue
		}

		break
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to rldp servers %s of host %s, err: %w", triedAddresses, host, err)
	}

	log.Info().Str("host", host).Str("node", hex.EncodeToString(id)).Str("address", addr).Msg("connected to server")

	info := &rldpInfo{
		ActiveClient: client,
		ID:           pubKey,
		Addr:         addr,
	}
	// DHT decoding returns pointers; PeerEndpoint accepts the address values.
	var endpoints []address.Address
	for _, raw := range addresses.Addresses {
		switch addr := raw.(type) {
		case *address.UDP:
			endpoints = append(endpoints, *addr)
		case *address.UDP6:
			endpoints = append(endpoints, *addr)
		case *address.QUIC:
			endpoints = append(endpoints, *addr)
		}
	}
	if endpoint, endpointErr := quic.PeerEndpoint(endpoints); endpointErr == nil {
		info.quicAddr = endpoint.String()
	}
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
