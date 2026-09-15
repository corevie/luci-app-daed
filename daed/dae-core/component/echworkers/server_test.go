/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Tests of the local SOCKS5/HTTP proxy server: SOCKS5 CONNECT, HTTP
 * CONNECT, plain HTTP proxying (request rebuilding + proxy header
 * stripping), SOCKS5 UDP ASSOCIATE for DNS (DoH over ECH), and the server
 * lifecycle. All traffic is relayed through the ECH mock tunnel of
 * tunnel_test.go.
 */

package echworkers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startTestProxy starts the proxy server of a client wired to a fresh mock
// tunnel and returns the client plus "127.0.0.1:port".
func startTestProxy(t *testing.T, dohURLPrefix string) (*Client, string) {
	t.Helper()
	server, echList := startMockTunnelServer(t, mockTunnelOpts{withECH: true})
	c, err := NewClient(Option{
		Server:             server,
		InsecureSkipVerify: true,
		Logger:             testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.echMu.Lock()
	c.echList = echList
	c.echMu.Unlock()
	c.dohURLPrefix = dohURLPrefix

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		c.StopProxyServer()
	})
	if err := c.StartProxyServer(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("StartProxyServer: %v", err)
	}
	addr := c.ProxyAddr()
	if addr == nil {
		t.Fatal("proxy server not listening")
	}
	return c, addr.String()
}

// socks5Connect performs a SOCKS5 CONNECT handshake toward target and
// returns the ready-to-use connection.
func socks5Connect(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Greeting: VER=5, one method, NO-AUTH.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, []byte{0x05, 0x00}) {
		t.Fatalf("SOCKS5 method reply = %x", reply)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := scanSscanf(portStr, &port); err != nil {
		t.Fatal(err)
	}
	// Request: VER=5 CMD=CONNECT RSV ATYP=domain.
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT reply = %x (code %d)", resp, resp[1])
	}
	return conn
}

func scanSscanf(s string, v *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	*v = n
	return 1, nil
}

func TestProxyServerSOCKS5Connect(t *testing.T) {
	echoAddr := startEchoServer(t)
	_, proxyAddr := startTestProxy(t, "")

	conn := socks5Connect(t, proxyAddr, echoAddr)
	if _, err := conn.Write([]byte("socks5 over ech tunnel")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "socks5 over ech tunnel" {
		t.Fatalf("echo = %q", buf[:n])
	}
}

func TestProxyServerSOCKS5FirstFrameOptimization(t *testing.T) {
	// Client payload sent right after the SOCKS5 request should ride the
	// CONNECT message (first frame) instead of a separate relay packet.
	echoAddr := startEchoServer(t)
	type connectInfo struct {
		target     string
		firstFrame string
	}
	connectSeen := make(chan connectInfo, 4)
	server, echList := startMockTunnelServer(t, mockTunnelOpts{
		withECH: true,
		connectHook: func(target, firstFrame string) {
			// Runs on the mock server's handler goroutine.
			connectSeen <- connectInfo{target: target, firstFrame: firstFrame}
		},
	})
	c, err := NewClient(Option{Server: server, InsecureSkipVerify: true, Logger: testLogger()})
	if err != nil {
		t.Fatal(err)
	}
	c.echMu.Lock()
	c.echList = echList
	c.echMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		c.StopProxyServer()
	})
	if err := c.StartProxyServer(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	proxyAddr := c.ProxyAddr().String()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Greeting + request in one batch, immediately followed by payload.
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := 0
	_, _ = scanSscanf(portStr, &port)
	req := []byte{0x05, 0x01, 0x00}
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	req = append(req, []byte("early-client-hello")...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	// Consume the method reply, the CONNECT reply, then the echo of the
	// early payload (which the tunnel delivered as the first frame).
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodReply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(methodReply, []byte{0x05, 0x00}) {
		t.Fatalf("method reply = %x", methodReply)
	}
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(conn, connectReply); err != nil {
		t.Fatal(err)
	}
	if connectReply[0] != 0x05 || connectReply[1] != 0x00 {
		t.Fatalf("connect reply = %x (code %d)", connectReply, connectReply[1])
	}

	var info connectInfo
	select {
	case info = <-connectSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("server never received a CONNECT with a first frame")
	}
	if info.target != echoAddr {
		t.Fatalf("connect target = %q, want %q", info.target, echoAddr)
	}
	if !strings.Contains(info.firstFrame, "early-client-hello") {
		t.Fatalf("first frame = %q, want it to contain the early payload", info.firstFrame)
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "early-client-hello" {
		t.Fatalf("echo = %q", buf[:n])
	}
}

func TestProxyServerHTTPConnect(t *testing.T) {
	echoAddr := startEchoServer(t)
	_, proxyAddr := startTestProxy(t, "")

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte("CONNECT " + echoAddr + " HTTP/1.1\r\nHost: " + echoAddr + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("CONNECT status = %q", statusLine)
	}
	// Drain the rest of the (empty) response headers.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	if _, err := conn.Write([]byte("http connect payload")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "http connect payload" {
		t.Fatalf("echo = %q", buf[:n])
	}
}

func TestProxyServerPlainHTTP(t *testing.T) {
	// Origin server: captures the forwarded request.
	var gotReq *http.Request
	var gotBody []byte
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("X-Origin", "yes")
		_, _ = w.Write([]byte("origin-response"))
	}))
	t.Cleanup(origin.Close)
	// The GET request carries no body; the captured value stays empty and
	// is only read to keep the closure honest.
	defer func() {
		if len(gotBody) != 0 {
			t.Fatalf("GET body should be empty, got %q", gotBody)
		}
	}()

	_, proxyAddr := startTestProxy(t, "")

	// GET with absolute-form request target and a Proxy-Connection header
	// that must be stripped.
	getURL := "http://" + origin.Listener.Addr().String() + "/some/path?x=1"
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	request := "GET " + getURL + " HTTP/1.1\r\n" +
		"Host: " + origin.Listener.Addr().String() + "\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"User-Agent: echworkers-test\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "origin-response" {
		t.Fatalf("origin body = %q", body)
	}
	if resp.Header.Get("X-Origin") != "yes" {
		t.Fatal("origin response headers not relayed")
	}
	if gotReq == nil {
		t.Fatal("origin never saw the request")
	}
	if gotReq.Method != "GET" || gotReq.URL.Path != "/some/path" || gotReq.URL.RawQuery != "x=1" {
		t.Fatalf("origin saw %v %v", gotReq.Method, gotReq.URL)
	}
	if gotReq.Header.Get("Proxy-Connection") != "" {
		t.Fatal("Proxy-Connection was not stripped")
	}
	if gotReq.Header.Get("User-Agent") != "echworkers-test" {
		t.Fatal("regular headers were dropped")
	}
}

func TestProxyServerPlainHTTPPostBody(t *testing.T) {
	var gotBody []byte
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(origin.Close)

	_, proxyAddr := startTestProxy(t, "")
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := "name=value&x=42"
	request := "POST http://" + origin.Listener.Addr().String() + "/submit HTTP/1.1\r\n" +
		"Host: " + origin.Listener.Addr().String() + "\r\n" +
		"Content-Length: " + itoa(len(payload)) + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"\r\n" + payload
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	if string(gotBody) != payload {
		t.Fatalf("origin body = %q, want %q", gotBody, payload)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestProxyServerUDPDNSViaDoH(t *testing.T) {
	canned := buildDNSResponse(t, []byte{0xfe, 0x0d}, true)
	doh := startHTTPHandler(t, func(w http.ResponseWriter, r map[string]any) {
		if r["path"] != "/dns-query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(canned)
	})
	t.Cleanup(doh.Close)

	_, proxyAddr := startTestProxy(t, doh.URL)

	// SOCKS5 UDP ASSOCIATE.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE reply = %x (code %d)", resp, resp[1])
	}
	udpPort := binary.BigEndian.Uint16(resp[8:10])

	// Send a DNS query for port 53 through the UDP relay.
	udpConn, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", itoa(int(udpPort))), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })
	dnsQuery := buildDNSQuery("cloudflare-ech.com", typeHTTPS)
	datagram := []byte{0x00, 0x00, 0x00 /*FRAG*/, 0x01 /*IPv4*/, 8, 8, 8, 8, 0x00, 0x35}
	datagram = append(datagram, dnsQuery...)
	if _, err := udpConn.Write(datagram); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4096)
	_ = udpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := udpConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("UDP response too short: %d bytes", n)
	}
	// The reply must carry the same SOCKS5 header and the canned payload.
	if !bytes.Equal(buf[:10], datagram[:10]) {
		t.Fatalf("reply SOCKS5 header = %x, want %x", buf[:10], datagram[:10])
	}
	if !bytes.Equal(buf[10:n], canned) {
		t.Fatalf("reply DNS payload mismatch: got %d bytes, want %d", n-10, len(canned))
	}
}

func TestProxyServerUnknownProtocol(t *testing.T) {
	_, proxyAddr := startTestProxy(t, "")
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{0x07}); err != nil {
		t.Fatal(err)
	}
	// The server must drop the connection without answering.
	buf := make([]byte, 16)
	if n, err := conn.Read(buf); n != 0 || err == nil {
		t.Fatalf("expected connection close, got %d bytes (err=%v)", n, err)
	}
}

func TestProxyServerLifecycle(t *testing.T) {
	server, echList := startMockTunnelServer(t, mockTunnelOpts{withECH: true})
	c, err := NewClient(Option{Server: server, InsecureSkipVerify: true, Logger: testLogger()})
	if err != nil {
		t.Fatal(err)
	}
	c.echMu.Lock()
	c.echList = echList
	c.echMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.StartProxyServer(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	addr := c.ProxyAddr().String()

	// Double start must fail.
	if err := c.StartProxyServer(ctx, "127.0.0.1:0"); err == nil {
		t.Fatal("expected error for double start")
	}

	// Stop releases the listener.
	c.StopProxyServer()
	if c.ProxyAddr() != nil {
		t.Fatal("ProxyAddr should be nil after stop")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listener not released after stop: %v", err)
	}
	_ = ln.Close()

	// Restart must succeed.
	if err := c.StartProxyServer(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	c.StopProxyServer()

	// Empty listen address must fail.
	if err := c.StartProxyServer(ctx, ""); err == nil {
		t.Fatal("expected error for empty listen address")
	}
}
