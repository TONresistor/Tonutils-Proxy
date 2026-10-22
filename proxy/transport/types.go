package transport

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sigurn/crc16"
	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func init() {
	tl.Register(Request{}, "http.request id:int256 method:string url:string http_version:string headers:(vector http.header) = http.Response")
	tl.Register(Response{}, "http.response http_version:string status_code:int reason:string headers:(vector http.header) no_payload:Bool = http.Response")
	tl.Register(GetNextPayloadPart{}, "http.getNextPayloadPart id:int256 seqno:int max_chunk_size:int = http.PayloadPart")
	tl.Register(PayloadPart{}, "http.payloadPart data:bytes trailer:(vector http.header) last:Bool = http.PayloadPart")
	tl.Register(GetCapabilities{}, "http.proxy.getCapabilities capabilities:long = http.proxy.Capabilities")
	tl.Register(Capabilities{}, "http.proxy.capabilities capabilities:long = http.proxy.Capabilities")
	tl.Register(Header{}, "http.header name:string value:string = http.Header")
}

type Request struct {
	ID      []byte   `tl:"int256"`
	Method  string   `tl:"string"`
	URL     string   `tl:"string"`
	Version string   `tl:"string"`
	Headers []Header `tl:"vector struct"`
}

type GetNextPayloadPart struct {
	ID           []byte `tl:"int256"`
	Seqno        int32  `tl:"int"`
	MaxChunkSize int32  `tl:"int"`
}

type Response struct {
	Version    string   `tl:"string"`
	StatusCode int32    `tl:"int"`
	Reason     string   `tl:"string"`
	Headers    []Header `tl:"vector struct"`
	NoPayload  bool     `tl:"bool"`
}

type PayloadPart struct {
	Data    []byte   `tl:"bytes"`
	Trailer []Header `tl:"vector struct"`
	IsLast  bool     `tl:"bool"`
}

type Header struct {
	Name  string `tl:"string"`
	Value string `tl:"string"`
}

type GetCapabilities struct {
	Capabilities int64 `tl:"long"`
}

type Capabilities struct {
	Value int64 `tl:"long"`
}

type httpClient interface {
	DoQuery(ctx context.Context, maxAnswerSize uint64, query, result tl.Serializable) error
}

type quicClient struct {
	peer      *quic.Peer
	failed    atomic.Bool
	transport *Transport
	owner     *quicOwner
	inFlight  atomic.Int64
}

func (c *quicClient) DoQuery(ctx context.Context, maxAnswerSize uint64, query, result tl.Serializable) (err error) {
	data, err := tl.Serialize(query, true)
	if err != nil {
		return fmt.Errorf("failed to serialize QUIC HTTP query: %w", err)
	}
	answer, err := c.peer.Query(ctx, data, int64(min(maxAnswerSize, uint64(quic.DefaultMaxObjectSize))))
	if err != nil {
		if errors.Is(err, quic.ErrPeerClosed) {
			c.markFailed()
		}
		// As in C++, a request already sent over QUIC fails without replay on RLDP.
		return fmt.Errorf("failed to query QUIC HTTP peer: %w", err)
	}
	return parseQUICHTTP(answer, result)
}

func (c *quicClient) markFailed() {
	if c.failed.CompareAndSwap(false, true) {
		c.transport.quicMx.Lock()
		for _, wake := range c.owner.users {
			notifyQUIC(wake)
		}
		c.transport.quicMx.Unlock()
	}
}

// The root reference lasts through Body.Close/EOF. Upload and payload-fetch
// goroutines retain their own references, so an early response cannot hide an
// upload still in progress from the idle cleaner.
type quicRequest struct {
	client *quicClient
	site   *siteInfo
	refs   atomic.Int32
}

func (c *quicClient) beginRequest(site *siteInfo) *quicRequest {
	c.inFlight.Add(1)
	atomic.AddInt64(&site.quicInFlight, 1)
	r := &quicRequest{client: c, site: site}
	r.refs.Store(1)
	r.touch()
	return r
}
func (r *quicRequest) touch()  { atomic.StoreInt64(&r.site.QUICLastUsed, time.Now().UnixNano()) }
func (r *quicRequest) retain() { r.refs.Add(1) }
func (r *quicRequest) release() {
	r.touch()
	if r.refs.Add(-1) == 0 {
		atomic.AddInt64(&r.site.quicInFlight, -1)
		r.client.inFlight.Add(-1)
		r.client.transport.closeUnusedQUIC(r.client)
	}
}
func (r *quicRequest) DoQuery(ctx context.Context, max uint64, query, result tl.Serializable) error {
	r.touch()
	defer r.touch()
	return r.client.DoQuery(ctx, max, query, result)
}

type quicResponseBody struct {
	io.ReadCloser
	flight *quicRequest
	once   sync.Once
}

func (b *quicResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.flight.touch()
	if err != nil {
		b.once.Do(b.flight.release)
	}
	return n, err
}
func (b *quicResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.flight.release)
	return err
}

func parseQUICHTTP(data []byte, result tl.Serializable) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("failed to parse QUIC HTTP object: %v", recovered)
		}
	}()

	rest, err := tl.Parse(result, data, true)
	if err != nil {
		return fmt.Errorf("failed to parse QUIC HTTP object: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("unexpected trailing QUIC HTTP data")
	}
	return nil
}

var crc16table = crc16.MakeTable(crc16.CRC16_XMODEM)

func ParseADNLAddress(addr string) ([]byte, error) {
	if len(addr) != 55 {
		return nil, errors.New("wrong id length")
	}

	buf, err := base32.StdEncoding.DecodeString("F" + strings.ToUpper(addr))
	if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}

	if buf[0] != 0x2d {
		return nil, errors.New("invalid first byte")
	}

	hash := binary.BigEndian.Uint16(buf[33:])
	calc := crc16.Checksum(buf[:33], crc16table)
	if hash != calc {
		return nil, errors.New("invalid address")
	}

	return buf[1:33], nil
}
