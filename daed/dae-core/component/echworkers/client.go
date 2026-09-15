/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Package echworkers ports the "ech-workers" tunnel client (originally
 * ech-workers原版/workers.go) into dae.
 *
 * The client connects to a WebSocket (wss://) tunnel server with TLS 1.3
 * Encrypted Client Hello (ECH), and exposes two ways to use the tunnel:
 *
 *  1. As a dae outbound node (scheme "echws://", see
 *     component/outbound/dialer/echws), so dae's routing engine can relay
 *     traffic through the tunnel like any other node.
 *  2. As a standalone local SOCKS5/HTTP proxy server (see server.go),
 *     preserving the behavior of the original StartSocksProxy.
 *
 * Tunnel wire protocol (identical to the original client):
 *
 *   C -> S: text   "CONNECT:<target>|<firstFrame>"
 *   S -> C: text   "CONNECTED" or "ERROR:<reason>"
 *   C <-> S: binary payload frames (bidirectional relay)
 *   C/S -> S/C: text "CLOSE" to tear down the tunnel
 *   C -> S: websocket ping every 10s to keep the tunnel alive
 */

package echworkers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

// Default option values, kept in sync with the original workers.go.
const (
	// DefaultDNSServer is the DoH server used to fetch the ECH config.
	DefaultDNSServer = "dns.alidns.com/dns-query"
	// DefaultEchDomain is the domain queried for its HTTPS (type 65) record.
	DefaultEchDomain = "cloudflare-ech.com"
	// DefaultMaxDialRetries is the retry budget of dialWebSocketWithECH.
	DefaultMaxDialRetries = 2
	// echRetryInterval is the delay between ECH fetch retries.
	echRetryInterval = 2 * time.Second
	// handshakeTimeout is the websocket (TLS) handshake timeout.
	handshakeTimeout = 10 * time.Second
	// dialTimeout is the plain TCP dial timeout to the tunnel server.
	dialTimeout = 10 * time.Second
	// keepAliveInterval is the websocket ping interval of a live tunnel.
	keepAliveInterval = 10 * time.Second
	// wsBufferSize is the read/write buffer size of the websocket dialer.
	wsBufferSize = 65536
)

// Option is the configuration of a tunnel Client.
type Option struct {
	// Server is the tunnel server in "host:port[/path]" form. Required.
	Server string
	// ServerIPs, when set, pins TCP connections to these IPs (in random
	// order per connection, failing over on retries) while keeping the TLS
	// SNI / ECH inner name from Server. Accepts plain IPs; "ip:port"
	// entries are tolerated (port is stripped).
	ServerIPs []string
	// Token is sent as the websocket subprotocol for authentication.
	Token string
	// InsecureSkipVerify skips TLS certificate verification toward the
	// tunnel server. Not recommended; mirrors the allowInsecure option of
	// other dae outbounds.
	InsecureSkipVerify bool
	// DNSServer is the DoH server ("host[/path]") used to fetch ECH configs.
	// Empty means DefaultDNSServer.
	DNSServer string
	// EchDomain is the domain whose HTTPS DNS record holds the ECH config.
	// Empty means DefaultEchDomain.
	EchDomain string
	// MaxDialRetries is how many times a tunnel dial is attempted (ECH
	// related failures trigger an ECH refresh between attempts).
	// Zero means DefaultMaxDialRetries.
	MaxDialRetries int
	// NextDialer optionally provides the underlying TCP dialer toward the
	// tunnel server. When nil, a plain net.Dialer is used (like the
	// original client).
	NextDialer netproxy.Dialer
	// Logger receives diagnostics. When nil, logrus.StandardLogger is used.
	Logger *logrus.Logger
}

// Client is a reusable ECH websocket tunnel client.
//
// A Client owns the ECH config cache for its server and is safe for
// concurrent use: each tunnel is an independent websocket connection while
// the ECH list is shared under a lock.
type Client struct {
	opt Option
	log *logrus.Entry

	echMu   sync.RWMutex
	echList []byte

	// serverIPCursor rotates over Option.ServerIPs so concurrent
	// connections spread across the candidate IPs and retries fail over to
	// the next one.
	serverIPCursor atomic.Uint64

	// dohURLPrefix, when set (tests only), overrides the hard-coded
	// https://cloudflare-dns.com DoH endpoint of QueryDoH.
	dohURLPrefix string

	proxyMu        sync.Mutex
	proxyListener  net.Listener
	proxyCtx       context.Context
	proxyCancel    context.CancelFunc
	proxyWaitGroup sync.WaitGroup
}

// pickServerIP returns the pinned server IP for one connection attempt,
// rotating over Option.ServerIPs (empty string = no pinning).
func (c *Client) pickServerIP() string {
	ips := c.opt.ServerIPs
	if len(ips) == 0 {
		return ""
	}
	// First call seeds a random start so independent processes spread
	// load over the candidates differently; afterwards it just rotates.
	if c.serverIPCursor.Load() == 0 {
		c.serverIPCursor.Store(rand.Uint64()%(1<<32) + 1)
	}
	next := c.serverIPCursor.Add(1)
	return ips[next%uint64(len(ips))]
}

// NewClient creates a tunnel client and validates its option.
func NewClient(opt Option) (*Client, error) {
	if opt.Server == "" {
		return nil, errors.New("echworkers: missing wss server address")
	}
	if _, _, _, err := ParseServerAddr(opt.Server); err != nil {
		return nil, fmt.Errorf("echworkers: %w", err)
	}
	if opt.DNSServer == "" {
		opt.DNSServer = DefaultDNSServer
	}
	if opt.EchDomain == "" {
		opt.EchDomain = DefaultEchDomain
	}
	if opt.MaxDialRetries <= 0 {
		opt.MaxDialRetries = DefaultMaxDialRetries
	}
	logger := opt.Logger
	if logger == nil {
		logger = logrus.StandardLogger()
	}
	opt.Logger = nil // not needed after resolving log.
	return &Client{
		opt: opt,
		log: logger.WithField("scope", "echworkers"),
	}, nil
}

// Server returns the configured tunnel server address.
func (c *Client) Server() string { return c.opt.Server }

// ======================== ECH 支持 ========================

// typeHTTPS is the DNS resource record type of HTTPS (SVCB).
const typeHTTPS = 65

// PrepareECH fetches the ECH config list via DoH and blocks until success,
// retrying every echRetryInterval. It returns when the config is loaded or
// ctx is done. This mirrors the original prepareECH retry loop.
func (c *Client) PrepareECH(ctx context.Context) error {
	for {
		echBase64, err := c.queryHTTPSRecord(ctx, c.opt.EchDomain, c.opt.DNSServer)
		if err != nil {
			c.log.WithError(err).Warnf("ECH DNS query via %v failed; retry in %v", c.opt.DNSServer, echRetryInterval)
		} else if echBase64 == "" {
			c.log.Warnf("no ECH config found for %v; retry in %v", c.opt.EchDomain, echRetryInterval)
		} else {
			raw, decodeErr := decodeBase64Std(echBase64)
			if decodeErr != nil {
				c.log.WithError(decodeErr).Warnf("ECH base64 decode failed; retry in %v", echRetryInterval)
			} else {
				c.echMu.Lock()
				c.echList = raw
				c.echMu.Unlock()
				c.log.Infof("ECHConfigList loaded: %d bytes", len(raw))
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(echRetryInterval):
		}
	}
}

// RefreshECH re-fetches the ECH config list (best effort, one shot).
func (c *Client) RefreshECH(ctx context.Context) error {
	c.log.Debugln("refreshing ECH config")
	echBase64, err := c.queryHTTPSRecord(ctx, c.opt.EchDomain, c.opt.DNSServer)
	if err != nil {
		return err
	}
	if echBase64 == "" {
		return fmt.Errorf("no ECH config found for %v", c.opt.EchDomain)
	}
	raw, err := decodeBase64Std(echBase64)
	if err != nil {
		return err
	}
	c.echMu.Lock()
	c.echList = raw
	c.echMu.Unlock()
	c.log.Infof("ECHConfigList refreshed: %d bytes", len(raw))
	return nil
}

// getECHList returns a copy of the current ECH config list.
func (c *Client) getECHList() ([]byte, error) {
	c.echMu.RLock()
	defer c.echMu.RUnlock()
	if len(c.echList) == 0 {
		return nil, errors.New("ECH config not loaded")
	}
	out := make([]byte, len(c.echList))
	copy(out, c.echList)
	return out, nil
}

// ECHReady reports whether an ECH config list has been loaded.
func (c *Client) ECHReady() bool {
	c.echMu.RLock()
	defer c.echMu.RUnlock()
	return len(c.echList) > 0
}

// SetECHConfigList installs a pre-fetched ECH config list, e.g. carried
// over from a previous client instance to avoid re-querying DoH.
func (c *Client) SetECHConfigList(list []byte) {
	c.echMu.Lock()
	c.echList = list
	c.echMu.Unlock()
}

// buildTLSConfigWithECH builds a TLS 1.3 client config that carries the
// ECH config list. If the server rejects ECH, the verification callback
// fails the handshake (no plaintext fallback).
func (c *Client) buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	var roots *x509.CertPool
	if !c.opt.InsecureSkipVerify {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system root certificates: %w", err)
		}
	}
	return &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		EncryptedClientHelloConfigList: echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("server rejected ECH")
		},
		RootCAs:            roots,
		InsecureSkipVerify: c.opt.InsecureSkipVerify,
	}, nil
}

// QueryDoH forwards a raw DNS query to Cloudflare DoH through a TLS+ECH
// connection (optionally pinned to the configured ServerIP). It backs the
// UDP DNS handling of the local proxy server, mirroring queryDoHForProxy.
func (c *Client) QueryDoH(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	// dohURLPrefix (tests only) replaces the hard-coded endpoint base.
	dohBase := c.dohURLPrefix
	if dohBase == "" {
		_, port, _, err := ParseServerAddr(c.opt.Server)
		if err != nil {
			return nil, err
		}
		dohBase = fmt.Sprintf("https://cloudflare-dns.com:%s", port)
	}
	dohURL := dohBase + "/dns-query"

	echBytes, err := c.getECHList()
	if err != nil {
		return nil, fmt.Errorf("failed to get ECH config: %w", err)
	}
	tlsCfg, err := c.buildTLSConfigWithECH("cloudflare-dns.com", echBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	transport := newECHHTTPTransport(tlsCfg, c.pickServerIP())
	client := &http.Client{Transport: transport, Timeout: dialTimeout}
	return dohPost(ctx, client, dohURL, dnsQuery)
}

// ======================== WebSocket 客户端 ========================

// ParseServerAddr splits "host:port[/path]" into its components. The path
// defaults to "/".
func ParseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	slashIdx := strings.Index(addr, "/")
	if slashIdx != -1 {
		path = addr[slashIdx:]
		addr = addr[:slashIdx]
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid server address format: %w", err)
	}
	return host, port, path, nil
}

// dialWebSocketWithECH dials the tunnel websocket with the ECH-enabled TLS
// config. On ECH related failures it refreshes the ECH config and retries,
// up to maxRetries attempts.
func (c *Client) dialWebSocketWithECH(ctx context.Context, maxRetries int) (*websocket.Conn, error) {
	host, port, path, err := ParseServerAddr(c.opt.Server)
	if err != nil {
		return nil, err
	}
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := c.getECHList()
		if echErr != nil {
			if attempt < maxRetries {
				if refreshErr := c.RefreshECH(ctx); refreshErr != nil {
					c.log.WithError(refreshErr).Debugln("ECH refresh failed during dial retry")
				}
				continue
			}
			return nil, echErr
		}

		tlsCfg, tlsErr := c.buildTLSConfigWithECH(host, echBytes)
		if tlsErr != nil {
			return nil, tlsErr
		}

		dialer := &websocket.Dialer{
			TLSClientConfig:  tlsCfg,
			HandshakeTimeout: handshakeTimeout,
			ReadBufferSize:   wsBufferSize,
			WriteBufferSize:  wsBufferSize,
		}
		if c.opt.Token != "" {
			dialer.Subprotocols = []string{c.opt.Token}
		}

		nextDialer := c.opt.NextDialer
		// Pick a fresh candidate on every attempt so retries fail over to
		// the next pinned IP.
		serverIP := c.pickServerIP()
		switch {
		case nextDialer != nil:
			dialer.NetDialContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				if serverIP != "" {
					_, port, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}
					addr = net.JoinHostPort(serverIP, port)
				}
				conn, err := nextDialer.DialContext(dialCtx, network, addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: fakeTCPAddr("127.0.0.1:0"),
					RAddr: fakeTCPAddr(addr),
				}, nil
			}
		case serverIP != "":
			dialer.NetDialContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				var d net.Dialer
				d.Timeout = dialTimeout
				return d.DialContext(dialCtx, network, net.JoinHostPort(serverIP, port))
			}
		}

		wsConn, _, dialErr := dialer.DialContext(ctx, wsURL, nil)
		if dialErr != nil {
			if strings.Contains(strings.ToLower(dialErr.Error()), "ech") && attempt < maxRetries {
				c.log.WithError(dialErr).Warnf("connection failed, refreshing ECH config (%d/%d)", attempt, maxRetries)
				if refreshErr := c.RefreshECH(ctx); refreshErr != nil {
					c.log.WithError(refreshErr).Debugln("ECH refresh failed during dial retry")
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Second):
				}
				continue
			}
			return nil, dialErr
		}
		return wsConn, nil
	}
	return nil, errors.New("connection failed: max retries reached")
}

// DialTunnel establishes a tunnel to target ("host:port") and performs the
// CONNECT handshake. firstFrame, when non-empty, is forwarded together with
// the CONNECT request to save one round trip (original protocol feature).
// The returned TunnelConn relays payload as binary websocket frames.
func (c *Client) DialTunnel(ctx context.Context, target string, firstFrame []byte) (*TunnelConn, error) {
	return c.dialTunnel(ctx, target, func() []byte { return firstFrame })
}

// dialTunnel is the general form of DialTunnel: firstFrameFn is invoked
// after the websocket connection is established but before the CONNECT
// message is sent, so the SOCKS5 server path can opportunistically capture
// early client payload there (exactly like the original client).
func (c *Client) dialTunnel(ctx context.Context, target string, firstFrameFn func() []byte) (*TunnelConn, error) {
	wsConn, err := c.dialWebSocketWithECH(ctx, c.opt.MaxDialRetries)
	if err != nil {
		return nil, err
	}

	var firstFrame []byte
	if firstFrameFn != nil {
		firstFrame = firstFrameFn()
	}
	tunnel := &TunnelConn{
		wsConn:  wsConn,
		log:     c.log,
		target:  target,
		closeCh: make(chan struct{}),
	}

	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, firstFrame)
	if err := tunnel.writeControlText(connectMsg); err != nil {
		_ = wsConn.Close()
		return nil, err
	}

	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		_ = wsConn.Close()
		return nil, err
	}
	response := string(msg)
	if strings.HasPrefix(response, "ERROR:") {
		_ = wsConn.Close()
		return nil, errors.New(response)
	}
	if response != "CONNECTED" {
		_ = wsConn.Close()
		return nil, fmt.Errorf("unexpected tunnel response: %s", response)
	}

	tunnel.startKeepAlive()
	c.log.Debugf("tunnel connected: %v", target)
	return tunnel, nil
}

// fakeTCPAddr builds a *net.TCPAddr for FakeNetConn bookkeeping. It is only
// informational; tunnel connections do not expose real socket addresses.
func fakeTCPAddr(addr string) net.Addr {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return &net.TCPAddr{}
	}
	return tcpAddr
}

// TunnelConn is a netproxy.Conn relaying through a websocket tunnel. Text
// frames are control messages: "CLOSE" tears the tunnel down; payload goes
// in binary frames. Writes (including keepalive pings) are serialized under
// writeMu because gorilla/websocket allows a single concurrent writer.
type TunnelConn struct {
	wsConn  *websocket.Conn
	log     *logrus.Entry
	target  string
	writeMu sync.Mutex

	readMu   sync.Mutex
	readBuf  []byte
	closeCh  chan struct{}
	closeOne sync.Once
}

// startKeepAlive pings the server every keepAliveInterval until closed.
func (t *TunnelConn) startKeepAlive() {
	go func() {
		ticker := time.NewTicker(keepAliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := t.writePing(); err != nil {
					return
				}
			case <-t.closeCh:
				return
			}
		}
	}()
}

func (t *TunnelConn) writeControlText(msg string) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.wsConn.WriteMessage(websocket.TextMessage, []byte(msg))
}

func (t *TunnelConn) writePing() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.wsConn.WriteMessage(websocket.PingMessage, nil)
}

// Read implements netproxy.Conn. It blocks until a payload frame (or a
// buffered remainder of the previous frame) is available.
func (t *TunnelConn) Read(b []byte) (n int, err error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	for len(t.readBuf) == 0 {
		msgType, msg, err := t.wsConn.ReadMessage()
		if err != nil {
			return 0, err
		}
		switch msgType {
		case websocket.TextMessage:
			if string(msg) == "CLOSE" {
				return 0, net.ErrClosed
			}
			// Other text frames are payload too (the original relay
			// forwards every non-CLOSE frame regardless of type).
			t.readBuf = msg
		default:
			t.readBuf = msg
		}
	}
	n = copy(b, t.readBuf)
	t.readBuf = t.readBuf[n:]
	return n, nil
}

// Write implements netproxy.Conn, sending payload as binary frames.
func (t *TunnelConn) Write(b []byte) (n int, err error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err = t.wsConn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close notifies the peer with "CLOSE" and tears down the tunnel. It is
// safe to call multiple times.
func (t *TunnelConn) Close() error {
	var err error
	t.closeOne.Do(func() {
		// Best effort close notification; ignore errors because the peer
		// or transport may already be gone.
		_ = t.writeControlText("CLOSE")
		err = t.wsConn.Close()
		close(t.closeCh)
	})
	return err
}

func (t *TunnelConn) SetDeadline(tm time.Time) error {
	if err := t.SetReadDeadline(tm); err != nil {
		return err
	}
	return t.SetWriteDeadline(tm)
}

func (t *TunnelConn) SetReadDeadline(tm time.Time) error {
	return t.wsConn.SetReadDeadline(tm)
}

func (t *TunnelConn) SetWriteDeadline(tm time.Time) error {
	return t.wsConn.SetWriteDeadline(tm)
}
