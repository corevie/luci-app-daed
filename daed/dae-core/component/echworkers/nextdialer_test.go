package echworkers

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// plainNextDialer dials TCP directly (test stand-in for dae's dialer stack).
type plainNextDialer struct{}

func (d *plainNextDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &netConnShim{conn}, nil
}

type netConnShim struct{ net.Conn }

// recordingNextDialer records every dialed address and forwards to a
// wrapped dialer.
type recordingNextDialer struct {
	inner netproxy.Dialer
	mu    sync.Mutex
	addrs []string
}

func (d *recordingNextDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, network+"|"+addr)
	d.mu.Unlock()
	return d.inner.DialContext(ctx, network, addr)
}

func (d *recordingNextDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// TestDoHBootstrapUsesNextDialer proves the ECH bootstrap DoH query goes
// through the configured NextDialer (in production: dae's marked direct
// dialer), so the eBPF data plane treats it as dae-originated traffic
// instead of re-capturing it.
func TestDoHBootstrapUsesNextDialer(t *testing.T) {
	canned := buildDNSResponse(t, []byte{0xfe, 0x0d, 0x00}, true)
	srv := startHTTPHandler(t, func(w http.ResponseWriter, r map[string]any) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(canned)
	})
	t.Cleanup(srv.Close)

	recorder := &recordingNextDialer{inner: &plainNextDialer{}}
	c, err := NewClient(Option{
		Server:             "example.com:443",
		DNSServer:          srv.URL + "/dns-query",
		NextDialer:         recorder,
		InsecureSkipVerify: true,
		Logger:             testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.RefreshECH(ctx); err != nil {
		t.Fatalf("RefreshECH: %v", err)
	}
	if !c.ECHReady() {
		t.Fatal("ECH config not loaded")
	}

	dialed := recorder.dialed()
	if len(dialed) == 0 {
		t.Fatal("DoH bootstrap did not go through NextDialer")
	}
	host, _, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dialed[0], host) {
		t.Fatalf("NextDialer dialed %v, want the DoH server %v", dialed, srv.Listener.Addr())
	}
}

func TestDialTunnelViaNextDialer(t *testing.T) {
	echoAddr := startEchoServer(t)
	server, echList := startMockTunnelServer(t, mockTunnelOpts{withECH: true})

	c, err := NewClient(Option{
		Server:             server,
		InsecureSkipVerify: true,
		NextDialer:         &plainNextDialer{},
		Logger:             testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.SetECHConfigList(echList)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tunnel, err := c.DialTunnel(ctx, echoAddr, nil)
	if err != nil {
		t.Fatalf("DialTunnel via NextDialer: %v", err)
	}
	defer func() { _ = tunnel.Close() }()
	if _, err := tunnel.Write([]byte("next-dialer")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := tunnel.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "next-dialer" {
		t.Fatalf("echo = %q", buf[:n])
	}
}

// TestPickServerIPRotates proves the pin IP rotates over the candidate
// list (random start, full coverage, no pin when empty).
func TestPickServerIPRotates(t *testing.T) {
	c, err := NewClient(Option{Server: "example.com:443", ServerIPs: []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		ip := c.pickServerIP()
		switch ip {
		case "1.1.1.1", "2.2.2.2", "3.3.3.3":
			seen[ip] = true
		default:
			t.Fatalf("pickServerIP returned %q", ip)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("rotation did not cover all candidates: %v", seen)
	}

	c2, err := NewClient(Option{Server: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	if ip := c2.pickServerIP(); ip != "" {
		t.Fatalf("pickServerIP without candidates = %q, want empty", ip)
	}
}

// TestDialTunnelPinsServerIP proves the WS dial connects to a pinned
// candidate instead of resolving the server hostname.
func TestDialTunnelPinsServerIP(t *testing.T) {
	echoAddr := startEchoServer(t)
	server, echList := startMockTunnelServer(t, mockTunnelOpts{withECH: true})

	// The mock tunnel listens on 127.0.0.1:<port>; the "server" hostname is
	// example.invalid so only the pin can reach it. The mocked NextDialer
	// rewrites any dialed addr to the mock server, recording what the
	// client asked for.
	recorder := &recordingNextDialer{inner: &rewriteDialer{target: server}}
	c, err := NewClient(Option{
		Server:             "example.invalid:443/tunnel",
		ServerIPs:          []string{"127.0.0.1"},
		InsecureSkipVerify: true,
		NextDialer:         recorder,
		Logger:             testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.SetECHConfigList(echList)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tunnel, err := c.DialTunnel(ctx, echoAddr, nil)
	if err != nil {
		t.Fatalf("DialTunnel with pinned IP: %v", err)
	}
	defer func() { _ = tunnel.Close() }()

	dialed := recorder.dialed()
	if len(dialed) == 0 {
		t.Fatal("NextDialer was never used")
	}
	if !strings.Contains(dialed[0], "127.0.0.1:") {
		t.Fatalf("dial addr = %v, want a pinned 127.0.0.1:port", dialed[0])
	}
	if strings.Contains(dialed[0], "example.invalid") {
		t.Fatalf("dial addr = %v, the hostname leaked through the pin", dialed[0])
	}
}

// rewriteDialer forwards every dial to a fixed target address (any path
// suffix of the target is stripped: only host:port is dialable).
type rewriteDialer struct {
	target string
}

func (d *rewriteDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	target := d.target
	if idx := strings.Index(target, "/"); idx >= 0 {
		target = target[:idx]
	}
	return (&plainNextDialer{}).DialContext(ctx, network, target)
}
