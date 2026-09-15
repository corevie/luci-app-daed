/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Tests of the "echws://" node link: URL parsing, round-trip export,
 * FromLinkRegister integration, and DialContext dispatch.
 */

package echws

import (
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
	"reflect"
	"strings"
	"testing"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/gorilla/websocket"
)

func TestParseECHWSURL(t *testing.T) {
	tests := []struct {
		name string
		link string
		want ECHWS
	}{
		{
			name: "minimal",
			link: "echws://example.com",
			want: ECHWS{Host: "example.com", Port: 443, Path: "/", Protocol: "echws"},
		},
		{
			name: "full",
			link: "echws://worker.example.com:8443/tunnel?token=tok&ip=1.2.3.4&dns=dns.alidns.com%2Fdns-query&ech=cloudflare-ech.com#my-node",
			want: ECHWS{
				Name:      "my-node",
				Host:      "worker.example.com",
				Port:      8443,
				Path:      "/tunnel",
				ServerIPs: []string{"1.2.3.4"},
				Token:     "tok",
				DNSServer: "dns.alidns.com/dns-query",
				EchDomain: "cloudflare-ech.com",
				Protocol:  "echws",
			},
		},
		{
			name: "alias params",
			link: "echws://a.com:443/x?serverip=9.9.9.9&doh=doh.example.com&echdomain=ech.example.com&allowInsecure=true",
			want: ECHWS{
				Host:          "a.com",
				Port:          443,
				Path:          "/x",
				ServerIPs:     []string{"9.9.9.9"},
				DNSServer:     "doh.example.com",
				EchDomain:     "ech.example.com",
				AllowInsecure: true,
				Protocol:      "echws",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseECHWSURL(tt.link)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Fatalf("ParseECHWSURL = %+v, want %+v", *got, tt.want)
			}
		})
	}

	t.Run("multi ip list", func(t *testing.T) {
		got, err := ParseECHWSURL("echws://w.com:443/t?ip=1.1.1.1,2.2.2.2,162.158.1.1:443,junk")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"1.1.1.1", "2.2.2.2", "162.158.1.1"}
		if !reflect.DeepEqual(got.ServerIPs, want) {
			t.Fatalf("ServerIPs = %v, want %v", got.ServerIPs, want)
		}
	})

	t.Run("bad scheme", func(t *testing.T) {
		if _, err := ParseECHWSURL("socks5://example.com:1080"); err == nil {
			t.Fatal("expected error for non-echws scheme")
		}
	})
	t.Run("bad port", func(t *testing.T) {
		if _, err := ParseECHWSURL("echws://example.com:notaport"); err == nil {
			t.Fatal("expected error for bad port")
		}
	})
}

func TestECHWSURLRoundTrip(t *testing.T) {
	orig := &ECHWS{
		Name:      "node",
		Host:      "worker.example.com",
		Port:      8443,
		Path:      "/tunnel",
		ServerIPs: []string{"1.2.3.4", "5.6.7.8"},
		Token:     "tok",
		DNSServer: "dns.alidns.com/dns-query",
		EchDomain: "cloudflare-ech.com",
		Protocol:  "echws",
	}
	link := orig.ExportToURL()
	parsed, err := ParseECHWSURL(link)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, orig) {
		t.Fatalf("round trip mismatch:\n%+v\n%+v", *parsed, *orig)
	}
}

func TestAddressAndServer(t *testing.T) {
	s := &ECHWS{Host: "h.com", Port: 443, Path: "/tunnel"}
	if s.Address() != "h.com:443" {
		t.Fatalf("Address = %v", s.Address())
	}
	if s.Server() != "h.com:443/tunnel" {
		t.Fatalf("Server = %v", s.Server())
	}
}

func TestFromLinkRegisterIntegration(t *testing.T) {
	// The scheme must be registered with the outbound link factory.
	link := "echws://worker.example.com:443/tunnel?token=t#node"
	d, property, err := D.NewNetproxyDialerFromLink(
		directDialerForTest(),
		&D.ExtraOption{},
		link,
	)
	if err != nil {
		t.Fatalf("NewNetproxyDialerFromLink: %v", err)
	}
	if property == nil {
		t.Fatal("property is nil")
	}
	if property.Name != "node" {
		t.Errorf("Name = %v", property.Name)
	}
	if property.Address != "worker.example.com:443" {
		t.Errorf("Address = %v", property.Address)
	}
	if property.Protocol != "echws" {
		t.Errorf("Protocol = %v", property.Protocol)
	}
	if _, ok := d.(*Dialer); !ok {
		t.Fatalf("dialer type = %T, want *echws.Dialer", d)
	}
}

// directDialerForTest provides a next dialer that dials localhost
// directly; it only needs to work for the local mock server.
func directDialerForTest() netproxy.Dialer {
	return &plainDialer{}
}

type plainDialer struct{}

func (d *plainDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &netConnAdapter{conn}, nil
}

type netConnAdapter struct {
	net.Conn
}

func TestDialContextUDPRejected(t *testing.T) {
	s := &ECHWS{Host: "example.com", Port: 443, Path: "/", Protocol: "echws"}
	d, _, err := s.Dialer(directDialerForTest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DialContext(context.Background(), "udp", "8.8.8.8:53"); err == nil {
		t.Fatal("expected UDP to be rejected")
	} else if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("UDP error = %v, want unsupported tunnel type", err)
	}
	if _, err := d.DialContext(context.Background(), "sctp", "example.com:80"); err == nil {
		t.Fatal("expected unknown network to be rejected")
	}
}

// The rest spins up a compact ECH mock tunnel so the TCP path is exercised
// through the exported DialContext.

func TestDialContextTCPThroughTunnel(t *testing.T) {
	echoAddr := startLocalEcho(t)
	server, echList := startLocalECHTunnel(t)

	s := &ECHWS{Host: hostOf(t, server), Port: portOf(t, server), Path: "/tunnel", AllowInsecure: true, Protocol: "echws"}
	d, property, err := s.Dialer(directDialerForTest())
	if err != nil {
		t.Fatal(err)
	}
	if property.Address != s.Address() {
		t.Fatalf("property address = %v, want %v", property.Address, s.Address())
	}
	// Install the mock server's ECH config list so no DoH bootstrap is
	// needed (in production DialContext bootstraps via DoH itself).
	d.(*Dialer).client.SetECHConfigList(echList)

	conn, err := d.DialContext(context.Background(), "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext tcp: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("echws dialer works")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "echws dialer works" {
		t.Fatalf("echo = %q", buf[:n])
	}
}

func hostOf(t *testing.T, addr string) string {
	t.Helper()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return port
}

func startLocalEcho(t *testing.T) string {
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

// startLocalECHTunnel starts a TLS+ECH websocket tunnel server and returns
// its address plus the ECH config list to install on the client.
func startLocalECHTunnel(t *testing.T) (addr string, echList []byte) {
	t.Helper()

	echPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	echList = buildLocalECHConfigList(echPriv.PublicKey().Bytes())

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		msgType, msg, err := ws.ReadMessage()
		if err != nil || msgType != websocket.TextMessage || !strings.HasPrefix(string(msg), "CONNECT:") {
			return
		}
		payload := strings.TrimPrefix(string(msg), "CONNECT:")
		idx := strings.Index(payload, "|")
		if idx < 0 {
			return
		}
		target, firstFrame := payload[:idx], payload[idx+1:]
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
		done := make(chan struct{}, 2)
		go func() {
			for {
				mt, data, err := ws.ReadMessage()
				if err != nil || (mt == websocket.TextMessage && string(data) == "CLOSE") {
					done <- struct{}{}
					return
				}
				if _, err := targetConn.Write(data); err != nil {
					done <- struct{}{}
					return
				}
			}
		}()
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := targetConn.Read(buf)
				if n > 0 {
					if ws.WriteMessage(websocket.BinaryMessage, buf[:n]) != nil {
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
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config:      echList[2:],
			PrivateKey:  echPriv.Bytes(),
			SendAsRetry: true,
		}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), echList
}

func buildLocalECHConfigList(pub []byte) []byte {
	publicName := "outer.example.com"
	contents := []byte{0x42}
	contents = append(contents, 0x00, 0x20)
	contents = append(contents, byte(len(pub)>>8), byte(len(pub)))
	contents = append(contents, pub...)
	suites := []byte{0x00, 0x01, 0x00, 0x01}
	contents = append(contents, byte(len(suites)>>8), byte(len(suites)))
	contents = append(contents, suites...)
	contents = append(contents, 0x00)
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = append(contents, 0x00, 0x00)
	cfg := []byte{0xfe, 0x0d, byte(len(contents) >> 8), byte(len(contents))}
	cfg = append(cfg, contents...)
	list := []byte{byte(len(cfg) >> 8), byte(len(cfg))}
	return append(list, cfg...)
}
