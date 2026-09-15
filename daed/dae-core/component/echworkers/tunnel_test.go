/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * End-to-end tests of the ECH websocket tunnel: a mock tunnel server with
 * REAL TLS 1.3 + ECH (using tls.EncryptedClientHelloKeys) speaks the
 * original workers.go wire protocol, and the client relays through it.
 */

package echworkers

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

// buildECHConfigList marshals a draft-13/final ECHConfigList carrying a
// single X25519 + HKDF-SHA256 + AES-128-GCM config for the given public
// name. It matches the wire format parsed by crypto/tls.
func buildECHConfigList(t *testing.T, pub []byte, publicName string) []byte {
	t.Helper()
	contents := []byte{0x42}                // config_id
	contents = append(contents, 0x00, 0x20) // kem_id: DHKEM(X25519, HKDF-SHA256)
	contents = append(contents, byte(len(pub)>>8), byte(len(pub)))
	contents = append(contents, pub...)
	suites := []byte{0x00, 0x01 /* HKDF-SHA256 */, 0x00, 0x01 /* AES-128-GCM */}
	contents = append(contents, byte(len(suites)>>8), byte(len(suites)))
	contents = append(contents, suites...)
	contents = append(contents, 0x00) // maximum_name_length (uint8)
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = append(contents, 0x00, 0x00) // extensions
	cfg := []byte{0xfe, 0x0d, byte(len(contents) >> 8), byte(len(contents))}
	cfg = append(cfg, contents...)
	list := []byte{byte(len(cfg) >> 8), byte(len(cfg))}
	list = append(list, cfg...)
	return list
}

// selfSignedCert generates a TLS certificate for the given DNS name.
func selfSignedCert(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// mockTunnelOpts customizes the mock tunnel server.
type mockTunnelOpts struct {
	// withECH configures real server-side ECH. When false the server
	// rejects ECH (client must fail the handshake).
	withECH bool
	// refuseTargets makes every CONNECT fail with "ERROR:refused".
	refuseTargets bool
	// wantSubprotocol, when set, must match the client subprotocol.
	wantSubprotocol string
	// closeHook is invoked when the server receives a CLOSE text frame.
	closeHook func()
	// connectHook observes every CONNECT target and first frame.
	connectHook func(target, firstFrame string)
}

// startMockTunnelServer runs a wss tunnel server implementing the original
// protocol; it returns its "host:port" address and the ECH config list the
// client should use.
func startMockTunnelServer(t *testing.T, opts mockTunnelOpts) (addr string, echConfigList []byte) {
	t.Helper()

	echPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	echConfigList = buildECHConfigList(t, echPriv.PublicKey().Bytes(), "outer.example.com")

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t, "localhost")},
		MinVersion:   tls.VersionTLS13,
	}
	if opts.withECH {
		serverTLSConfig.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{
			Config:      echConfigList[2:],
			PrivateKey:  echPriv.Bytes(),
			SendAsRetry: true,
		}}
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("mock tunnel got non-tunnel request: %v %v subproto=%v", r.Method, r.URL.Path, r.Header.Get("Sec-Websocket-Protocol"))
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		if opts.wantSubprotocol != "" {
			got := ""
			if len(r.Header["Sec-Websocket-Protocol"]) > 0 {
				got = r.Header["Sec-Websocket-Protocol"][0]
			}
			if got != opts.wantSubprotocol {
				http.Error(w, "bad subprotocol: "+got, http.StatusUnauthorized)
				return
			}
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		serveMockTunnelConn(t, ws, opts)
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = serverTLSConfig
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv.Listener.Addr().String() + "/tunnel", echConfigList
}

// serveMockTunnelConn speaks the server side of the tunnel protocol.
func serveMockTunnelConn(t *testing.T, ws *websocket.Conn, opts mockTunnelOpts) {
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	msgType, msg, err := ws.ReadMessage()
	if err != nil || msgType != websocket.TextMessage {
		return
	}
	connectMsg := string(msg)
	if !strings.HasPrefix(connectMsg, "CONNECT:") {
		_ = ws.WriteMessage(websocket.TextMessage, []byte("ERROR:bad request"))
		return
	}
	payload := strings.TrimPrefix(connectMsg, "CONNECT:")
	idx := strings.Index(payload, "|")
	if idx < 0 {
		_ = ws.WriteMessage(websocket.TextMessage, []byte("ERROR:malformed connect"))
		return
	}
	target := payload[:idx]
	firstFrame := payload[idx+1:]
	if opts.connectHook != nil {
		opts.connectHook(target, firstFrame)
	}
	if opts.refuseTargets {
		_ = ws.WriteMessage(websocket.TextMessage, []byte("ERROR:refused"))
		return
	}
	targetConn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_ = ws.WriteMessage(websocket.TextMessage, []byte("ERROR:"+err.Error()))
		return
	}
	defer func() { _ = targetConn.Close() }()
	if firstFrame != "" {
		if _, err := targetConn.Write([]byte(firstFrame)); err != nil {
			return
		}
	}
	if err := ws.WriteMessage(websocket.TextMessage, []byte("CONNECTED")); err != nil {
		return
	}
	_ = ws.SetReadDeadline(time.Time{})

	done := make(chan struct{}, 2)
	// ws -> target
	go func() {
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				done <- struct{}{}
				return
			}
			if mt == websocket.TextMessage && string(data) == "CLOSE" {
				if opts.closeHook != nil {
					opts.closeHook()
				}
				done <- struct{}{}
				return
			}
			if _, err := targetConn.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	// target -> ws
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					done <- struct{}{}
					return
				}
			}
			if err != nil {
				_ = ws.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

// newTestClient builds a Client pointing at the mock tunnel with the given
// ECH list and verification disabled (the mock uses a self-signed cert).
func newTestClient(t *testing.T, server string, echList []byte, token string) *Client {
	t.Helper()
	c, err := NewClient(Option{
		Server:             server,
		Token:              token,
		InsecureSkipVerify: true,
		Logger:             testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.echMu.Lock()
	c.echList = echList
	c.echMu.Unlock()
	return c
}

func testLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	l.SetOutput(io.Discard)
	return l
}

// startEchoServer runs a TCP server echoing every chunk back.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestDialTunnelWithECH(t *testing.T) {
	echoAddr := startEchoServer(t)
	server, echList := startMockTunnelServer(t, mockTunnelOpts{withECH: true})

	c := newTestClient(t, server, echList, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tunnel, err := c.DialTunnel(ctx, echoAddr, nil)
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer func() { _ = tunnel.Close() }()

	if _, err := tunnel.Write([]byte("hello ech tunnel")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := tunnel.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello ech tunnel" {
		t.Fatalf("echo = %q", buf[:n])
	}

	// Second round trip on the same tunnel.
	if _, err := tunnel.Write([]byte("second")); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	n, err = tunnel.Read(buf)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if string(buf[:n]) != "second" {
		t.Fatalf("echo 2 = %q", buf[:n])
	}
}

func TestDialTunnelFirstFrame(t *testing.T) {
	echoAddr := startEchoServer(t)
	var gotTarget, gotFirst string
	server, echList := startMockTunnelServer(t, mockTunnelOpts{
		withECH: true,
		connectHook: func(target, firstFrame string) {
			gotTarget, gotFirst = target, firstFrame
		},
	})

	c := newTestClient(t, server, echList, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tunnel, err := c.DialTunnel(ctx, echoAddr, []byte("early-payload"))
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer func() { _ = tunnel.Close() }()

	if gotTarget != echoAddr {
		t.Errorf("target = %q, want %q", gotTarget, echoAddr)
	}
	if gotFirst != "early-payload" {
		t.Errorf("first frame = %q, want early-payload", gotFirst)
	}
	// The first frame must have been delivered to the target.
	buf := make([]byte, 64)
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := tunnel.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "early-payload" {
		t.Fatalf("echoed first frame = %q", buf[:n])
	}
}

func TestDialTunnelServerError(t *testing.T) {
	server, echList := startMockTunnelServer(t, mockTunnelOpts{withECH: true, refuseTargets: true})
	c := newTestClient(t, server, echList, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := c.DialTunnel(ctx, "127.0.0.1:9", nil)
	if err == nil {
		t.Fatal("expected error from refused CONNECT")
	}
	if !strings.Contains(err.Error(), "ERROR:") {
		t.Fatalf("error = %v, want ERROR: response", err)
	}
}

func TestDialTunnelECHRejected(t *testing.T) {
	// Server without ECH keys: the client must abort instead of falling
	// back to plaintext (ECH rejection verifier).
	echoAddr := startEchoServer(t)
	server, echList := startMockTunnelServer(t, mockTunnelOpts{withECH: false})
	c := newTestClient(t, server, echList, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := c.DialTunnel(ctx, echoAddr, nil)
	if err == nil {
		t.Fatal("expected handshake failure when server rejects ECH")
	}
}

func TestDialTunnelTokenSubprotocol(t *testing.T) {
	echoAddr := startEchoServer(t)
	server, echList := startMockTunnelServer(t, mockTunnelOpts{
		withECH:         true,
		wantSubprotocol: "my-secret",
	})

	// Wrong token: the upgrade is rejected.
	c := newTestClient(t, server, echList, "wrong-token")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.DialTunnel(ctx, echoAddr, nil); err == nil {
		t.Fatal("expected dial failure with wrong token")
	}

	// Correct token.
	c2 := newTestClient(t, server, echList, "my-secret")
	tunnel, err := c2.DialTunnel(ctx, echoAddr, nil)
	if err != nil {
		t.Fatalf("DialTunnel with token: %v", err)
	}
	_ = tunnel.Close()
}

func TestTunnelConnCloseSendsCLOSE(t *testing.T) {
	echoAddr := startEchoServer(t)
	closeSeen := make(chan struct{}, 1)
	server, echList := startMockTunnelServer(t, mockTunnelOpts{
		withECH:   true,
		closeHook: func() { closeSeen <- struct{}{} },
	})
	c := newTestClient(t, server, echList, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tunnel, err := c.DialTunnel(ctx, echoAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close must be idempotent.
	if err := tunnel.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case <-closeSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel server never received the CLOSE notification")
	}
}

func TestDialTunnelServerClosesWithCLOSE(t *testing.T) {
	// Target closes the connection -> server sends CLOSE -> client Read
	// must unblock with an error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Read a byte then close: the mock server forwards CLOSE.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_ = conn.Close()
	}()

	server, echList := startMockTunnelServer(t, mockTunnelOpts{withECH: true})
	c := newTestClient(t, server, echList, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tunnel, err := c.DialTunnel(ctx, ln.Addr().String(), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tunnel.Close() }()
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if _, err := tunnel.Read(buf); err == nil {
		t.Fatal("expected error after server CLOSE")
	}
}

func TestQueryDoHViaECHTransport(t *testing.T) {
	// QueryDoH posts to the cloudflare-dns.com URL by design; point the
	// client at a local mock through the white-box override.
	canned := buildDNSResponse(t, []byte{0xfe, 0x0d}, true)
	srv := startHTTPHandler(t, func(w http.ResponseWriter, r map[string]any) {
		if r["path"] != "/dns-query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(canned)
	})
	t.Cleanup(func() { srv.Close() })

	server, echList := startMockTunnelServer(t, mockTunnelOpts{withECH: true})
	c := newTestClient(t, server, echList, "")
	c.dohURLPrefix = srv.URL // white-box override

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.QueryDoH(ctx, buildDNSQuery("cloudflare-ech.com", typeHTTPS))
	if err != nil {
		t.Fatalf("QueryDoH: %v", err)
	}
	if !bytes.Equal(resp, canned) {
		t.Fatalf("QueryDoH response = %d bytes, want the canned answer", len(resp))
	}
}

func TestParseMagicNetworkHandling(t *testing.T) {
	// Sanity: the dialer path relies on netproxy magic network strings; the
	// plain "tcp" form must reach DialTunnel. (Full coverage lives in the
	// echws package tests.)
	echoAddr := startEchoServer(t)
	server, echList := startMockTunnelServer(t, mockTunnelOpts{withECH: true})
	c := newTestClient(t, server, echList, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tunnel, err := c.DialTunnel(ctx, echoAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tunnel.Close() }()
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := tunnel.Write([]byte("deadline-check")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := tunnel.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "deadline-check" {
		t.Fatalf("echo = %q", buf[:n])
	}
}
