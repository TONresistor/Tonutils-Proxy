package transport

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-storage/storage"
)

type lifecycleTestRLDP struct {
	closed chan struct{}
	once   sync.Once
}

func (r *lifecycleTestRLDP) Close() {
	r.once.Do(func() { close(r.closed) })
}

func (r *lifecycleTestRLDP) DoQuery(context.Context, uint64, tl.Serializable, tl.Serializable) error {
	return nil
}

func (r *lifecycleTestRLDP) SetOnQuery(func([]byte, *rldp.Query) error) {}
func (r *lifecycleTestRLDP) SetOnDisconnect(func())                     {}
func (r *lifecycleTestRLDP) SendAnswer(context.Context, uint64, uint32, []byte, []byte, tl.Serializable) error {
	return nil
}
func (r *lifecycleTestRLDP) GetADNL() rldp.ADNL { return nil }

type lifecycleTestDownloader struct {
	ctx context.Context
}

func (d *lifecycleTestDownloader) Close()         {}
func (d *lifecycleTestDownloader) IsActive() bool { return d.ctx.Err() == nil }

func TestCleanerClosesIdleRLDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &lifecycleTestRLDP{closed: make(chan struct{})}
	transport := &Transport{
		activeSites: map[string]*siteInfo{
			"idle.ton": {
				Actor:    &rldpInfo{ActiveClient: client},
				LastUsed: time.Now().Add(-10 * time.Minute).Unix(),
			},
		},
		globalCtx: ctx,
	}

	done := make(chan struct{})
	go func() {
		transport.cleaner()
		close(done)
	}()

	select {
	case <-client.closed:
	case <-time.After(4 * time.Second):
		t.Fatal("idle RLDP client was not closed")
	}

	if _, ok := transport.activeSites["idle.ton"]; ok {
		t.Fatal("idle RLDP site was not evicted")
	}

	cancel()
	<-done
}

func TestCleanerKeepsActiveRLDPStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &lifecycleTestRLDP{closed: make(chan struct{})}
	transport := &Transport{
		activeSites: map[string]*siteInfo{
			"streaming.ton": {
				Actor:         &rldpInfo{ActiveClient: client},
				LastUsed:      time.Now().Add(-10 * time.Minute).Unix(),
				ActiveStreams: 1,
			},
		},
		globalCtx: ctx,
	}

	done := make(chan struct{})
	go func() {
		transport.cleaner()
		close(done)
	}()

	select {
	case <-client.closed:
		t.Fatal("active RLDP stream was closed as idle")
	case <-time.After(3500 * time.Millisecond):
	}

	cancel()
	<-done
}

func TestPrepareKeepsActorUsedByActiveStream(t *testing.T) {
	client := &lifecycleTestRLDP{closed: make(chan struct{})}
	actor := &rldpInfo{ActiveClient: client}
	info := &siteInfo{
		Actor:         actor,
		LastUsed:      time.Now().Unix(),
		LastSuccess:   time.Now().Add(-10 * time.Minute).Unix(),
		ActiveStreams: 1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport := &Transport{globalCtx: ctx}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://streaming.ton/", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err = info.prepare(transport, req); err != nil {
		t.Fatal(err)
	}
	if info.Actor != actor {
		t.Fatal("actor used by an active stream was replaced")
	}
	select {
	case <-client.closed:
		t.Fatal("actor used by an active stream was closed")
	default:
	}
}

func TestReplaceActorClosesOldRLDP(t *testing.T) {
	client := &lifecycleTestRLDP{closed: make(chan struct{})}
	info := &siteInfo{Actor: &rldpInfo{ActiveClient: client}}

	info.replaceActor(&Transport{}, &bagInfo{})

	select {
	case <-client.closed:
	case <-time.After(time.Second):
		t.Fatal("replaced RLDP actor was not closed")
	}
}

func TestStopClosesCachedActors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &lifecycleTestRLDP{closed: make(chan struct{})}
	transport := &Transport{
		activeSites: map[string]*siteInfo{
			"cached.ton": {Actor: &rldpInfo{ActiveClient: client}},
		},
		globalCtx:   ctx,
		stop:        cancel,
		cleanerDone: make(chan struct{}),
	}
	go transport.cleaner()

	transport.Stop()

	select {
	case <-client.closed:
	case <-time.After(time.Second):
		t.Fatal("global stop did not close cached RLDP actor")
	}
	if len(transport.activeSites) != 0 {
		t.Fatal("global stop did not clear cached sites")
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
