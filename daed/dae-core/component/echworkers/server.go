/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Local SOCKS5/HTTP proxy server of the ech-workers tunnel client.
 *
 * This file ports the unified proxy server of the original workers.go: one
 * TCP listener auto-detects SOCKS5 (first byte 0x05) and HTTP (CONNECT,
 * GET, POST, ...) clients. TCP traffic is relayed through the ECH
 * websocket tunnel; SOCKS5 UDP ASSOCIATE is supported for DNS only, which
 * is answered via DoH carried over ECH.
 */

package echworkers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Proxy mode of a client connection.
const (
	modeSOCKS5      = 1 // SOCKS5 proxy
	modeHTTPConnect = 2 // HTTP CONNECT tunnel
	modeHTTPProxy   = 3 // plain HTTP proxy (GET/POST/...)
)

// Server-side tunings, identical to the original workers.go.
const (
	// proxyInitialDeadline bounds protocol detection of a fresh client.
	proxyInitialDeadline = 30 * time.Second
	// firstFrameWait is how long the SOCKS5 path peeks at early client
	// payload to merge it into the CONNECT request.
	firstFrameWait = 100 * time.Millisecond
	// relayBufferSize is the copy buffer of both relay directions.
	relayBufferSize = 32768
	// udpReadDeadline is the polling interval of the UDP relay loop.
	udpReadDeadline = time.Second
	// httpBodyLimit bounds the buffered HTTP request body.
	httpBodyLimit = 10 * 1024 * 1024
)

// isNormalCloseError reports whether err is an expected connection
// teardown (EOF, local close, broken pipe, peer reset) that should not be
// logged as a proxy failure.
func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure")
}

// StartProxyServer prepares the ECH config and serves the unified
// SOCKS5/HTTP proxy on listenAddr until ctx is done. It is the dae
// counterpart of the original StartSocksProxy.
//
// The ECH bootstrap blocks first (retrying until it succeeds or ctx is
// done), then the listener is bound; a bind failure is reported to the
// caller instead of being swallowed by the serving goroutine.
func (c *Client) StartProxyServer(ctx context.Context, listenAddr string) error {
	if listenAddr == "" {
		return errors.New("echworkers: empty proxy listen address")
	}
	// Bootstrap the ECH config first (blocking, retrying), unless a config
	// is already loaded (e.g. the controller restarted the server with the
	// same client after a listen address change).
	if !c.ECHReady() {
		if err := c.PrepareECH(ctx); err != nil {
			return fmt.Errorf("echworkers: ECH bootstrap failed: %w", err)
		}
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("echworkers: proxy listen failed: %w", err)
	}
	c.proxyMu.Lock()
	if c.proxyListener != nil {
		c.proxyMu.Unlock()
		_ = listener.Close()
		return errors.New("echworkers: proxy server already started")
	}
	c.proxyListener = listener
	c.proxyCtx, c.proxyCancel = context.WithCancel(ctx)
	proxyCtx := c.proxyCtx
	c.proxyMu.Unlock()

	c.log.Infof("proxy server started: %v (SOCKS5 and HTTP)", listenAddr)
	c.log.Infof("tunnel server: %v", c.opt.Server)
	if len(c.opt.ServerIPs) > 0 {
		c.log.Infof("tunnel server IPs pinned to: %v (rotating)", c.opt.ServerIPs)
	}

	// Close the listener when ctx is done so shutdown cannot leak the
	// accept loop even if StopProxyServer is not called.
	go func() {
		<-proxyCtx.Done()
		_ = listener.Close()
	}()

	c.proxyWaitGroup.Add(1)
	go func() {
		defer c.proxyWaitGroup.Done()
		c.runProxyServer(proxyCtx, listener)
	}()
	return nil
}

// StopProxyServer stops the proxy server. It is the counterpart of the
// original StopSocksProxy, but synchronous so callers can rely on the
// listener being released when it returns.
func (c *Client) StopProxyServer() {
	c.proxyMu.Lock()
	listener := c.proxyListener
	cancel := c.proxyCancel
	c.proxyListener = nil
	c.proxyCancel = nil
	c.proxyCtx = nil
	c.proxyMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if listener != nil {
		_ = listener.Close()
	}
	// Give in-flight handlers a moment to observe the shutdown; they
	// finish on their own once their sockets drain.
	done := make(chan struct{})
	go func() {
		c.proxyWaitGroup.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
	if listener != nil {
		c.log.Infoln("proxy server stopped")
	}
}

// ProxyAddr returns the bound address of the running proxy server, or nil
// when it is not running (useful for 127.0.0.1:0 style listeners).
func (c *Client) ProxyAddr() net.Addr {
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	if c.proxyListener == nil {
		return nil
	}
	return c.proxyListener.Addr()
}

// runProxyServer accepts client connections and dispatches each of them to
// a handler goroutine, until the listener is closed.
func (c *Client) runProxyServer(ctx context.Context, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			continue
		}
		c.proxyWaitGroup.Add(1)
		go func() {
			defer c.proxyWaitGroup.Done()
			c.handleConnection(ctx, conn)
		}()
	}
}

// handleConnection reads the first byte to detect the client protocol.
func (c *Client) handleConnection(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	clientAddr := conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(proxyInitialDeadline))

	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	firstByte := buf[0]
	switch firstByte {
	case 0x05:
		// SOCKS5.
		c.handleSOCKS5(ctx, conn, clientAddr, firstByte)
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		// HTTP (CONNECT, GET, POST, HEAD, DELETE, OPTIONS, TRACE, PUT...).
		c.handleHTTP(ctx, conn, clientAddr, firstByte)
	default:
		c.log.Warnf("%v: unknown protocol: 0x%02x", clientAddr, firstByte)
	}
}

// ======================== SOCKS5 处理 ========================

// handleSOCKS5 serves a SOCKS5 client: CONNECT is relayed through the
// tunnel; UDP ASSOCIATE is accepted for DNS (answered via DoH); BIND is
// rejected.
func (c *Client) handleSOCKS5(ctx context.Context, conn net.Conn, clientAddr string, firstByte byte) {
	if firstByte != 0x05 {
		c.log.Warnf("[SOCKS5] %v: bad version: 0x%02x", clientAddr, firstByte)
		return
	}

	// Authentication methods.
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	nmethods := buf[0]
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// No-auth.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request.
	buf = make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != 5 {
		return
	}
	command := buf[1]
	atyp := buf[3]

	var host string
	switch atyp {
	case 0x01: // IPv4
		buf = make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 0x03: // Domain
		buf = make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		domainBuf := make([]byte, buf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)
	case 0x04: // IPv6
		buf = make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// Port.
	buf = make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])

	switch command {
	case 0x01: // CONNECT
		var target string
		if atyp == 0x04 {
			target = fmt.Sprintf("[%s]:%d", host, port)
		} else {
			target = fmt.Sprintf("%s:%d", host, port)
		}
		c.log.Infof("[SOCKS5] %v -> %v", clientAddr, target)
		if err := c.handleTunnel(ctx, conn, target, clientAddr, modeSOCKS5, nil); err != nil {
			if !isNormalCloseError(err) {
				c.log.Warnf("[SOCKS5] %v: proxy failed: %v", clientAddr, err)
			}
		}
	case 0x03: // UDP ASSOCIATE
		c.handleUDPAssociate(ctx, conn, clientAddr)
	default:
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
}

// handleUDPAssociate binds a loopback UDP socket for the client and keeps
// the TCP association alive until the client goes away.
func (c *Client) handleUDPAssociate(ctx context.Context, tcpConn net.Conn, clientAddr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		c.log.Warnf("[UDP] %v: failed to resolve address: %v", clientAddr, err)
		_, _ = tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		c.log.Warnf("[UDP] %v: failed to listen: %v", clientAddr, err)
		_, _ = tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	port := localAddr.Port
	c.log.Infof("[UDP] %v: UDP ASSOCIATE listening port: %d", clientAddr, port)

	// Success reply: BND.ADDR = 127.0.0.1, BND.PORT = port.
	response := []byte{0x05, 0x00, 0x00, 0x01}
	response = append(response, 127, 0, 0, 1)
	response = append(response, byte(port>>8), byte(port&0xff))
	if _, err := tcpConn.Write(response); err != nil {
		_ = udpConn.Close()
		return
	}

	stopChan := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.handleUDPRelay(ctx, udpConn, clientAddr, stopChan)
	}()

	// Keep the TCP connection until the client closes it.
	buf := make([]byte, 1)
	_, _ = tcpConn.Read(buf)

	close(stopChan)
	_ = udpConn.Close()
	wg.Wait()
	c.log.Infof("[UDP] %v: UDP ASSOCIATE closed", clientAddr)
}

// handleUDPRelay parses SOCKS5 UDP datagrams. Only port-53 (DNS) traffic
// is supported; it is answered asynchronously via DoH over ECH.
func (c *Client) handleUDPRelay(ctx context.Context, udpConn *net.UDPConn, clientAddr string, stopChan chan struct{}) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-stopChan:
			return
		case <-ctx.Done():
			return
		default:
		}

		_ = udpConn.SetReadDeadline(time.Now().Add(udpReadDeadline))
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		if n < 10 {
			continue
		}
		data := buf[:n]
		if data[2] != 0x00 { // FRAG must be 0
			continue
		}

		atyp := data[3]
		var headerLen int
		var dstHost string
		var dstPort int
		switch atyp {
		case 0x01: // IPv4
			dstHost = net.IP(data[4:8]).String()
			dstPort = int(data[8])<<8 | int(data[9])
			headerLen = 10
		case 0x03: // Domain
			domainLen := int(data[4])
			if n < 7+domainLen {
				continue
			}
			dstHost = string(data[5 : 5+domainLen])
			dstPort = int(data[5+domainLen])<<8 | int(data[6+domainLen])
			headerLen = 7 + domainLen
		case 0x04: // IPv6
			if n < 22 {
				continue
			}
			dstHost = net.IP(data[4:20]).String()
			dstPort = int(data[20])<<8 | int(data[21])
			headerLen = 22
		default:
			continue
		}

		udpData := data[headerLen:]
		target := fmt.Sprintf("%s:%d", dstHost, dstPort)

		if dstPort == 53 {
			c.log.Infof("[UDP-DNS] %v -> %v (DoH query)", clientAddr, target)
			// Copy the datagram: the relay loop reuses buf.
			payload := make([]byte, len(udpData))
			copy(payload, udpData)
			header := make([]byte, headerLen)
			copy(header, data[:headerLen])
			go func(from *net.UDPAddr) {
				c.handleDNSQuery(ctx, udpConn, from, payload, header)
			}(addr)
		} else {
			c.log.Infof("[UDP] %v -> %v (non-DNS UDP is not supported)", clientAddr, target)
		}
	}
}

// handleDNSQuery answers a client DNS datagram by forwarding the query to
// Cloudflare DoH over TLS+ECH and wrapping the response in the SOCKS5 UDP
// header of the request.
func (c *Client) handleDNSQuery(ctx context.Context, udpConn *net.UDPConn, clientAddr *net.UDPAddr, dnsQuery []byte, socks5Header []byte) {
	dnsResponse, err := c.QueryDoH(ctx, dnsQuery)
	if err != nil {
		c.log.Warnf("[UDP-DNS] DoH query failed: %v", err)
		return
	}

	response := make([]byte, 0, len(socks5Header)+len(dnsResponse))
	response = append(response, socks5Header...)
	response = append(response, dnsResponse...)

	if _, err := udpConn.WriteToUDP(response, clientAddr); err != nil {
		c.log.Warnf("[UDP-DNS] failed to send response: %v", err)
		return
	}
	c.log.Infof("[UDP-DNS] DoH query succeeded, response %d bytes", len(dnsResponse))
}

// ======================== HTTP 处理 ========================

// handleHTTP serves an HTTP client: CONNECT tunnels are relayed with a 200
// response; plain requests are rebuilt with relative request targets and
// relayed transparently.
func (c *Client) handleHTTP(ctx context.Context, conn net.Conn, clientAddr string, firstByte byte) {
	// Put the consumed byte back and parse the request from a buffered
	// reader.
	reader := bufio.NewReader(io.MultiReader(
		strings.NewReader(string(firstByte)),
		conn,
	))

	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return
	}
	method := parts[0]
	requestURL := parts[1]
	httpVersion := parts[2]

	headers := make(map[string]string)
	var headerLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		headerLines = append(headerLines, line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[strings.ToLower(key)] = value
		}
	}

	switch method {
	case "CONNECT":
		c.log.Infof("[HTTP-CONNECT] %v -> %v", clientAddr, requestURL)
		if err := c.handleTunnel(ctx, conn, requestURL, clientAddr, modeHTTPConnect, nil); err != nil {
			if !isNormalCloseError(err) {
				c.log.Warnf("[HTTP-CONNECT] %v: proxy failed: %v", clientAddr, err)
			}
		}

	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE":
		c.log.Infof("[HTTP-%s] %v -> %v", method, clientAddr, requestURL)

		var target, path string
		if strings.HasPrefix(requestURL, "http://") {
			// Absolute-form request target.
			urlWithoutScheme := strings.TrimPrefix(requestURL, "http://")
			idx := strings.Index(urlWithoutScheme, "/")
			if idx > 0 {
				target = urlWithoutScheme[:idx]
				path = urlWithoutScheme[idx:]
			} else {
				target = urlWithoutScheme
				path = "/"
			}
		} else {
			// Relative path: take authority from Host.
			target = headers["host"]
			path = requestURL
		}
		if target == "" {
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		if !strings.Contains(target, ":") {
			target += ":80"
		}

		// Rebuild the request with a relative target, dropping
		// proxy-specific headers.
		var requestBuilder strings.Builder
		requestBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, httpVersion))
		for _, line := range headerLines {
			key := strings.Split(line, ":")[0]
			keyLower := strings.ToLower(strings.TrimSpace(key))
			if keyLower != "proxy-connection" && keyLower != "proxy-authorization" {
				requestBuilder.WriteString(line)
				requestBuilder.WriteString("\r\n")
			}
		}
		requestBuilder.WriteString("\r\n")

		// Append the request body when present.
		if contentLength := headers["content-length"]; contentLength != "" {
			var length int
			_, _ = fmt.Sscanf(contentLength, "%d", &length)
			if length > 0 && length < httpBodyLimit {
				body := make([]byte, length)
				if _, err := io.ReadFull(reader, body); err == nil {
					requestBuilder.Write(body)
				}
			}
		}
		firstFrame := []byte(requestBuilder.String())

		// modeHTTPProxy: no 200 response; relay the origin response as-is.
		if err := c.handleTunnel(ctx, conn, target, clientAddr, modeHTTPProxy, firstFrame); err != nil {
			if !isNormalCloseError(err) {
				c.log.Warnf("[HTTP-%s] %v: proxy failed: %v", method, clientAddr, err)
			}
		}

	default:
		c.log.Warnf("[HTTP] %v: unsupported method: %v", clientAddr, method)
		_, _ = conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
	}
}

// ======================== 通用隧道处理 ========================

// handleTunnel relays one client connection through the websocket tunnel.
func (c *Client) handleTunnel(ctx context.Context, conn net.Conn, target, clientAddr string, mode int, firstFrame []byte) error {
	// Opportunistically capture early SOCKS5 client payload between the
	// websocket dial and the CONNECT message, saving one round trip. The
	// peek mirrors the original client: a short read deadline that is
	// cleared right after.
	firstFrameFn := func() []byte { return firstFrame }
	if len(firstFrame) == 0 && mode == modeSOCKS5 {
		firstFrameFn = func() []byte {
			_ = conn.SetReadDeadline(time.Now().Add(firstFrameWait))
			buffer := make([]byte, relayBufferSize)
			n, _ := conn.Read(buffer)
			_ = conn.SetReadDeadline(time.Time{})
			return buffer[:n]
		}
	}
	tunnel, err := c.dialTunnel(ctx, target, firstFrameFn)
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}
	defer func() { _ = tunnel.Close() }()

	_ = conn.SetDeadline(time.Time{})

	if err := sendSuccessResponse(conn, mode); err != nil {
		return err
	}
	c.log.Infof("%v connected: %v", clientAddr, target)

	// Bidirectional relay.
	done := make(chan bool, 2)

	// Client -> Server.
	go func() {
		buf := make([]byte, relayBufferSize)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				// Notify the server, then let the deferred Close finish
				// the teardown.
				_ = tunnel.Close()
				done <- true
				return
			}
			if _, err := tunnel.Write(buf[:n]); err != nil {
				done <- true
				return
			}
		}
	}()

	// Server -> Client.
	go func() {
		buf := make([]byte, relayBufferSize)
		for {
			n, err := tunnel.Read(buf)
			if err != nil {
				done <- true
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
		}
	}()

	<-done
	c.log.Infof("%v disconnected: %v", clientAddr, target)
	return nil
}

// ======================== 响应辅助函数 ========================

// sendErrorResponse answers a failed tunnel setup according to the client
// protocol.
func sendErrorResponse(conn net.Conn, mode int) {
	switch mode {
	case modeSOCKS5:
		_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case modeHTTPConnect, modeHTTPProxy:
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

// sendSuccessResponse acknowledges an established tunnel according to the
// client protocol.
func sendSuccessResponse(conn net.Conn, mode int) error {
	switch mode {
	case modeSOCKS5:
		_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return err
	case modeHTTPConnect:
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		return err
	case modeHTTPProxy:
		// Plain HTTP proxying relays the origin response directly.
		return nil
	}
	return nil
}
