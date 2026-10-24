package main

// Every analysis runs under guardAnalysis: it holds one of NumCPU slots, is
// cancelled when the client leaves or analyzeTimeout passes, and is watched by
// a watchdog that exits the process (for the container to restart it) when an
// analysis outlives hardTimeout — the only way out of a hang inside C code.
// A parsed CRL costs memory in proportion to its entries, so CRLs above
// bigCRLSize are parsed and processed one at a time. Up to bigCRLQueue
// analyses waiting for that turn give their slot back meanwhile, so raw CRLs
// held in memory stay bounded by slots plus that queue. Request bodies and
// /api/der responses over bigTransferSize are admitted bigTransfers at a time.
//
// External data is untrusted: every fetch is bounded by size and time for its
// kind, an analysis makes at most maxFetches of them, only the first few URLs
// of each kind in a certificate are followed, and a URL that failed — or any
// URL on an endpoint that could not be connected to — is not retried for the
// cache TTL. A shared download is cancelled when its last waiter leaves.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PiDmitrius/certview/internal/ssrfguard"
)

const (
	analyzeTimeout  = 3 * time.Minute
	slotWait        = 30 * time.Second
	hardTimeout     = 10 * time.Minute
	bigCRLSize      = 16 << 20
	bigCRLQueue     = 2
	bigTransfers    = 2
	bigTransferSize = 1 << 20
	maxPending      = 64

	maxCRLSize       = 128 << 20
	maxFetches       = 20
	maxAIAURLs       = 3
	maxCDPURLs       = 3
	maxOCSPURLs      = 2
	maxAIACerts      = 32
	maxAltCandidates = 8
	archiveSample    = 16
	maxChainDepth    = 10
)

type fetchKind struct {
	name     string
	maxBytes int64
	timeout  time.Duration // 0: only the client's idle and overall timeouts
}

var (
	fetchAIA  = fetchKind{"AIA", 1 << 20, 15 * time.Second}
	fetchCRL  = fetchKind{"CRL", maxCRLSize, 0}
	fetchOCSP = fetchKind{"OCSP", 64 << 10, 15 * time.Second}
)

var (
	errBusy  = errors.New("server busy, try again later")
	slots    = make(chan struct{}, runtime.NumCPU())
	pending  = make(chan struct{}, maxPending)
	bigDER   = make(chan struct{}, bigTransfers)
	bigCRL   = make(chan struct{}, 1)
	bigIO    = make(chan struct{}, bigTransfers)
	crlQueue = make(chan struct{}, bigCRLQueue)
	running  sync.Map // request id → start time
	inflight = &fetchFlight{calls: map[string]*fetchCall{}, failed: map[string]failure{}}

	errBudget      = fmt.Errorf("fetch budget of %d per analysis exhausted", maxFetches)
	errUnreachable = errors.New("unreachable")
)

// unreachableError is a failure to connect to addr (host:port as dialed,
// which after a redirect is not the requested URL's endpoint).
type unreachableError struct {
	addr string
	err  error
}

func (e *unreachableError) Error() string        { return "unreachable " + e.addr + ": " + e.err.Error() }
func (e *unreachableError) Unwrap() error        { return e.err }
func (e *unreachableError) Is(target error) bool { return target == errUnreachable }

type budgetKey struct{}

type slotKey struct{}

// slotHold records whether an analysis currently owns its slot.
type slotHold struct{ held atomic.Bool }

func guardAnalysis(ctx context.Context, rl reqLog) (context.Context, func(), error) {
	wait, stopWait := context.WithTimeout(ctx, slotWait)
	defer stopWait()
	select {
	case slots <- struct{}{}:
	case <-wait.Done():
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		rl.f("busy: no analysis slot within %s", slotWait)
		return nil, nil, errBusy
	}
	running.Store(rl.id, time.Now())
	budget := new(atomic.Int32)
	budget.Store(maxFetches)
	ctx = context.WithValue(ctx, budgetKey{}, budget)
	hold := &slotHold{}
	hold.held.Store(true)
	ctx = context.WithValue(ctx, slotKey{}, hold)
	ctx, cancel := context.WithTimeout(ctx, analyzeTimeout)
	return ctx, func() {
		cancel()
		running.Delete(rl.id)
		if hold.held.Load() {
			<-slots
		}
	}, nil
}

func acquireCRLMemory(ctx context.Context, size int) (func(), error) {
	if size < bigCRLSize {
		return func() {}, nil
	}
	release := func() { <-bigCRL }
	select {
	case bigCRL <- struct{}{}:
		return release, nil
	default:
	}
	hold, _ := ctx.Value(slotKey{}).(*slotHold)
	select {
	case crlQueue <- struct{}{}:
		defer func() { <-crlQueue }()
	default:
		hold = nil
	}
	if hold != nil {
		hold.held.Store(false)
		<-slots
	}
	select {
	case bigCRL <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if hold == nil {
		return release, nil
	}
	// Never wait for a slot while holding the gate: slot holders may be
	// waiting for the gate. Without a free slot, give the gate back, take a
	// slot, then wait for the gate like any slot holder.
	select {
	case slots <- struct{}{}:
		hold.held.Store(true)
		return release, nil
	default:
	}
	release()
	select {
	case slots <- struct{}{}:
		hold.held.Store(true)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case bigCRL <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// admit bounds the requests that hold input or wait for an analysis: beyond
// maxPending they are refused at once, before reading a body.
func admit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case pending <- struct{}{}:
			defer func() { <-pending }()
			next(w, r)
		default:
			http.Error(w, errBusy.Error(), http.StatusServiceUnavailable)
		}
	}
}

// localOnly serves only requests addressed to localhost, so a web page in the
// administrator's browser cannot reach the admin listener by DNS rebinding.
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		switch strings.Trim(host, "[]") {
		case "localhost", "127.0.0.1", "::1":
		default:
			http.Error(w, "admin is served on localhost only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// acquireBig admits a transfer of size bytes (-1 if unknown) through sem;
// small ones pass freely. The returned release may be called more than once.
func acquireBig(ctx context.Context, sem chan struct{}, size int64) (func(), error) {
	if size >= 0 && size <= bigTransferSize {
		return func() {}, nil
	}
	wait, stop := context.WithTimeout(ctx, slotWait)
	defer stop()
	select {
	case sem <- struct{}{}:
		return sync.OnceFunc(func() { <-sem }), nil
	case <-wait.Done():
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errBusy
	}
}

func runWatchdog() {
	for range time.Tick(15 * time.Second) {
		running.Range(func(id, start any) bool {
			if age := time.Since(start.(time.Time)); age > hardTimeout {
				log.Printf("watchdog: [r%04d] running for %s, exiting for restart", id, age.Round(time.Second))
				os.Exit(2)
			}
			return true
		})
	}
}

// writeAnalysisError maps guard errors to HTTP; a gone client gets nothing.
func writeAnalysisError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBusy):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	case errors.Is(err, context.DeadlineExceeded):
		http.Error(w, "analysis timed out", http.StatusGatewayTimeout)
	case errors.Is(err, context.Canceled):
	default:
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

func spendFetch(ctx context.Context) error {
	if n, ok := ctx.Value(budgetKey{}).(*atomic.Int32); ok && n.Add(-1) < 0 {
		return errBudget
	}
	return nil
}

// usableURLs returns the first max http(s) URLs.
func usableURLs(urls []string, max int) []string {
	var out []string
	for _, u := range urls {
		if len(out) == max {
			break
		}
		if l := strings.ToLower(u); strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			out = append(out, u)
		}
	}
	return out
}

// sizeError is input over its limit; n is -1 when only known to exceed it.
type sizeError struct{ n, max int64 }

func (e *sizeError) Error() string {
	if e.n < 0 {
		return fmt.Sprintf("too large: over %d bytes", e.max)
	}
	return fmt.Sprintf("too large: %d bytes, limit %d", e.n, e.max)
}

// statusError is an HTTP response other than 200 OK.
type statusError struct{ code int }

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

// recentFailure is a fetch refused because the same one failed within ttl.
type recentFailure struct {
	ttl time.Duration
	err error
}

func (e *recentFailure) Error() string {
	return fmt.Sprintf("failed within the last %s: %v", e.ttl, e.err)
}
func (e *recentFailure) Unwrap() error { return e.err }

var errNotObject = errors.New("not a DER or PEM object")

func readLimited(r io.Reader, contentLength, max int64) ([]byte, error) {
	if contentLength > max {
		return nil, &sizeError{contentLength, max}
	}
	var buf bytes.Buffer
	if contentLength > 0 {
		buf.Grow(int(contentLength) + 1)
	}
	if _, err := buf.ReadFrom(io.LimitReader(r, max+1)); err != nil {
		return nil, err
	}
	data := buf.Bytes()
	if int64(len(data)) > max {
		return nil, &sizeError{-1, max}
	}
	return data, nil
}

// publicError names a failed fetch for clients by its kind only: the text of
// a network error can carry internal addresses or another service's banner.
// The full error goes to the log.
func publicError(err error) string {
	var recent *recentFailure
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case errors.As(err, &recent):
		return "failed within the last " + recent.ttl.String() + ": " + publicError(recent.err)
	case errors.Is(err, ssrfguard.ErrBlocked):
		return "address is not public"
	case errors.As(err, &dnsErr):
		return "name not resolved"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.Is(err, errUnreachable):
		return "connection failed"
	case errors.Is(err, errBudget), errors.Is(err, errNotObject), errors.As(err, new(*statusError)), errors.As(err, new(*sizeError)):
		return err.Error()
	default:
		return "connection failed or invalid response"
	}
}

// checkObjectStart peeks whether a body starts as PEM or as a DER SEQUENCE
// of at most max bytes, so a download of anything else ends at once.
func checkObjectStart(br *bufio.Reader, max int64) error {
	head, _ := br.Peek(6)
	if bytes.HasPrefix(head, []byte("-----")) {
		return nil
	}
	if len(head) < 2 || head[0] != 0x30 {
		return errNotObject
	}
	n, size := int64(head[1]), int64(2)
	if n >= 0x80 {
		k := int(n & 0x7f)
		if k == 0 || k > 4 || len(head) < 2+k {
			return errNotObject
		}
		n = 0
		for _, b := range head[2 : 2+k] {
			n = n<<8 | int64(b)
		}
		size += int64(k)
	}
	if size += n; size > max {
		return &sizeError{size, max}
	}
	return nil
}

// fetchFlight shares one download per key between concurrent requests and
// remembers failures for failTTL. The download itself is bounded by its kind
// and the guarded client's timeouts, not by any single waiter, so one leaving
// client does not fail the others.
type fetchFlight struct {
	mu      sync.Mutex
	calls   map[string]*fetchCall
	failed  map[string]failure
	failTTL time.Duration
	swept   time.Time
}

type failure struct {
	err   error
	until time.Time
}

type fetchCall struct {
	done        chan struct{}
	cancel      context.CancelFunc
	waiters     int
	data        []byte
	contentType string
	err         error
}

// do fetches under key; a failure to connect to the endpoint itself
// (scheme://host:port) also marks the endpoint.
func (f *fetchFlight) do(ctx context.Context, kind fetchKind, key, endpoint string, fetch func(context.Context) ([]byte, string, error)) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	hostKey := "endpoint " + endpoint
	f.mu.Lock()
	for _, k := range []string{key, hostKey} {
		if fl, ok := f.failed[k]; ok {
			if time.Now().Before(fl.until) {
				f.mu.Unlock()
				return nil, "", &recentFailure{f.failTTL, fl.err}
			}
			delete(f.failed, k)
		}
	}
	if err := spendFetch(ctx); err != nil {
		f.mu.Unlock()
		return nil, "", err
	}
	c, ok := f.calls[key]
	if !ok {
		fctx, cancel := context.WithCancel(context.Background())
		if kind.timeout > 0 {
			fctx, cancel = context.WithTimeout(fctx, kind.timeout)
		}
		c = &fetchCall{done: make(chan struct{}), cancel: cancel}
		f.calls[key] = c
		go func() {
			c.data, c.contentType, c.err = fetch(fctx)
			abandoned := errors.Is(fctx.Err(), context.Canceled)
			cancel()
			f.mu.Lock()
			if f.calls[key] == c {
				delete(f.calls, key)
			}
			if c.err != nil && !abandoned && f.failTTL > 0 {
				now := time.Now()
				if len(f.failed) >= 4096 && now.Sub(f.swept) > 10*time.Second {
					f.swept = now
					for k, fl := range f.failed {
						if now.After(fl.until) {
							delete(f.failed, k)
						}
					}
				}
				f.failed[key] = failure{c.err, now.Add(f.failTTL)}
				var ue *unreachableError
				if errors.As(c.err, &ue) && strings.EqualFold(strings.SplitN(endpoint, "://", 2)[1], ue.addr) {
					f.failed[hostKey] = failure{c.err, now.Add(f.failTTL)}
				}
			}
			f.mu.Unlock()
			close(c.done)
		}()
	}
	c.waiters++
	f.mu.Unlock()
	select {
	case <-c.done:
		return c.data, c.contentType, c.err
	case <-ctx.Done():
		f.mu.Lock()
		if c.waiters--; c.waiters == 0 {
			c.cancel()
			if f.calls[key] == c {
				delete(f.calls, key)
			}
		}
		f.mu.Unlock()
		return nil, "", ctx.Err()
	}
}
