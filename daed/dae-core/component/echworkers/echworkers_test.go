/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Unit tests of the ech-workers helpers: DNS wire-format codec, server
 * address parsing, client option defaults, and TLS/ECH config building.
 */

package echworkers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// startHTTPHandler runs a local HTTP server that reports each request to
// the handler as {method, path, query, body} and lets it write the
// response.
func startHTTPHandler(t *testing.T, respond func(w http.ResponseWriter, req map[string]any)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		respond(w, map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  r.URL.RawQuery,
			"body":   body,
		})
	}))
}

func TestBuildDNSQuery(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		qtype  uint16
		want   []byte
	}{
		{
			name:   "single label",
			domain: "localhost",
			qtype:  65,
			want: append(
				append(
					[]byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					append([]byte{0x09}, []byte("localhost")...)...,
				),
				0x00, 0x00, 0x41, 0x00, 0x01,
			),
		},
		{
			name:   "multi label https",
			domain: "cloudflare-ech.com",
			qtype:  65,
			want: []byte{
				0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x0e, 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e', '-', 'e', 'c', 'h',
				0x03, 'c', 'o', 'm',
				0x00, 0x00, 0x41, 0x00, 0x01,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildDNSQuery(tt.domain, tt.qtype)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("buildDNSQuery(%v) = %x, want %x", tt.domain, got, tt.want)
			}
		})
	}
}

// buildDNSResponse builds a DNS response with one HTTPS answer carrying an
// ECH SvcParam (key 5).
func buildDNSResponse(t *testing.T, echValue []byte, withECH bool) []byte {
	t.Helper()
	question := append([]byte{byte(len("cloudflare-ech"))}, []byte("cloudflare-ech")...)
	question = append(question, 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x41, 0x00, 0x01)

	// Answer: name pointer (0xc00c), type HTTPS(65), class IN, ttl, rdata.
	rdata := []byte{0x00, 0x01}                   // SvcPriority = 1
	rdata = append(rdata, 0x00)                   // target name = "."
	rdata = append(rdata, 0x00, 0x01, 0x00, 0x00) // alpn key 1, empty value
	if withECH {
		rdata = append(rdata, 0x00, 0x05, byte(len(echValue)>>8), byte(len(echValue)))
		rdata = append(rdata, echValue...)
	}

	answer := []byte{0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, byte(len(rdata) >> 8), byte(len(rdata))}
	answer = append(answer, rdata...)

	resp := []byte{
		0x00, 0x01, // ID
		0x81, 0x80, // flags
		0x00, 0x01, // QDCOUNT
		0x00, 0x01, // ANCOUNT
		0x00, 0x00, 0x00, 0x00,
	}
	resp = append(resp, question...)
	resp = append(resp, answer...)
	return resp
}

func TestParseDNSResponse(t *testing.T) {
	echValue := []byte{0xfe, 0x0d, 0x00, 0x29, 0x01}

	t.Run("with ech", func(t *testing.T) {
		resp := buildDNSResponse(t, echValue, true)
		got, err := parseDNSResponse(resp)
		if err != nil {
			t.Fatal(err)
		}
		want := base64.StdEncoding.EncodeToString(echValue)
		if got != want {
			t.Fatalf("parseDNSResponse = %v, want %v", got, want)
		}
	})

	t.Run("without ech", func(t *testing.T) {
		resp := buildDNSResponse(t, nil, false)
		got, err := parseDNSResponse(resp)
		if err != nil {
			t.Fatal(err)
		}
		if got != "" {
			t.Fatalf("parseDNSResponse = %v, want empty", got)
		}
	})

	t.Run("too short", func(t *testing.T) {
		if _, err := parseDNSResponse([]byte{0x00, 0x01}); err == nil {
			t.Fatal("expected error for short response")
		}
	})

	t.Run("no answers", func(t *testing.T) {
		resp := []byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		if _, err := parseDNSResponse(resp); err == nil {
			t.Fatal("expected error for zero answers")
		}
	})

	t.Run("truncated answer", func(t *testing.T) {
		resp := buildDNSResponse(t, echValue, true)
		if _, err := parseDNSResponse(resp[:len(resp)-3]); err != nil {
			t.Logf("truncated response returned err (acceptable): %v", err)
		}
	})
}

func TestParseHTTPSRecord(t *testing.T) {
	build := func(svcPriority []byte, target []byte, params map[uint16][]byte) []byte {
		data := svcPriority
		data = append(data, target...)
		for key := range params {
			// Deliberately unsorted map: sort keys for determinism.
			_ = key
		}
		keys := make([]int, 0, len(params))
		for k := range params {
			keys = append(keys, int(k))
		}
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				if keys[j] < keys[i] {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}
		for _, k := range keys {
			v := params[uint16(k)]
			data = append(data, byte(k>>8), byte(k), byte(len(v)>>8), byte(len(v)))
			data = append(data, v...)
		}
		return data
	}

	t.Run("ech present", func(t *testing.T) {
		ech := []byte{0xde, 0xad, 0xbe, 0xef}
		// Root target name "." is a single 0x00.
		data := build([]byte{0x00, 0x01}, []byte{0x00}, map[uint16][]byte{
			1: {},             // alpn
			5: ech,            // ech
			4: {127, 0, 0, 1}, // ipv4hint
		})
		got := parseHTTPSRecord(data)
		want := base64.StdEncoding.EncodeToString(ech)
		if got != want {
			t.Fatalf("parseHTTPSRecord = %v, want %v", got, want)
		}
	})

	t.Run("domain target name", func(t *testing.T) {
		target := []byte{0x03, 'a', 'b', 'c', 0x00}
		data := build([]byte{0x00, 0xff}, target, map[uint16][]byte{5: {0x01}})
		if got := parseHTTPSRecord(data); got != base64.StdEncoding.EncodeToString([]byte{0x01}) {
			t.Fatalf("parseHTTPSRecord = %v", got)
		}
	})

	t.Run("no ech", func(t *testing.T) {
		data := build([]byte{0x00, 0x01}, []byte{0x00}, map[uint16][]byte{1: {0x02, 'h', '2'}})
		if got := parseHTTPSRecord(data); got != "" {
			t.Fatalf("parseHTTPSRecord = %v, want empty", got)
		}
	})

	t.Run("truncated param", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x00, 0x00, 0x05, 0xff, 0x00}
		if got := parseHTTPSRecord(data); got != "" {
			t.Fatalf("parseHTTPSRecord = %v, want empty for truncated param", got)
		}
	})

	t.Run("short rdata", func(t *testing.T) {
		if got := parseHTTPSRecord([]byte{0x00}); got != "" {
			t.Fatalf("parseHTTPSRecord = %v, want empty for short rdata", got)
		}
	})
}

func TestParseServerAddr(t *testing.T) {
	tests := []struct {
		addr string
		host string
		port string
		path string
		ok   bool
	}{
		{"example.com:443", "example.com", "443", "/", true},
		{"example.com:443/tunnel", "example.com", "443", "/tunnel", true},
		{"example.com:8443/a/b", "example.com", "8443", "/a/b", true},
		{"[2606:4700::6810:85e5]:443/ws", "2606:4700::6810:85e5", "443", "/ws", true},
		{"example.com", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			host, port, path, err := ParseServerAddr(tt.addr)
			if tt.ok != (err == nil) {
				t.Fatalf("ParseServerAddr(%v) error = %v, want ok=%v", tt.addr, err, tt.ok)
			}
			if err == nil && (host != tt.host || port != tt.port || path != tt.path) {
				t.Fatalf("ParseServerAddr(%v) = %v,%v,%v; want %v,%v,%v", tt.addr, host, port, path, tt.host, tt.port, tt.path)
			}
		})
	}
}

func TestIsNormalCloseError(t *testing.T) {
	normal := []error{
		io.EOF,
		net.ErrClosed,
		errors.New("use of closed network connection"),
		errors.New("write tcp: broken pipe"),
		errors.New("read tcp: connection reset by peer"),
		errors.New("websocket: close 1000 (normal closure)"),
	}
	for _, err := range normal {
		if !isNormalCloseError(err) {
			t.Errorf("isNormalCloseError(%v) = false, want true", err)
		}
	}
	abnormal := []error{
		nil,
		errors.New("connection refused"),
		errors.New("tls: handshake failure"),
	}
	for _, err := range abnormal {
		if isNormalCloseError(err) {
			t.Errorf("isNormalCloseError(%v) = true, want false", err)
		}
	}
}

func TestNewClient(t *testing.T) {
	t.Run("missing server", func(t *testing.T) {
		if _, err := NewClient(Option{}); err == nil {
			t.Fatal("expected error for empty server")
		}
	})
	t.Run("bad server format", func(t *testing.T) {
		if _, err := NewClient(Option{Server: "no-port.example.com"}); err == nil {
			t.Fatal("expected error for server without port")
		}
	})
	t.Run("defaults", func(t *testing.T) {
		c, err := NewClient(Option{Server: "example.com:443"})
		if err != nil {
			t.Fatal(err)
		}
		if c.opt.DNSServer != DefaultDNSServer {
			t.Errorf("DNSServer = %v, want %v", c.opt.DNSServer, DefaultDNSServer)
		}
		if c.opt.EchDomain != DefaultEchDomain {
			t.Errorf("EchDomain = %v, want %v", c.opt.EchDomain, DefaultEchDomain)
		}
		if c.opt.MaxDialRetries != DefaultMaxDialRetries {
			t.Errorf("MaxDialRetries = %v, want %v", c.opt.MaxDialRetries, DefaultMaxDialRetries)
		}
		if c.Server() != "example.com:443" {
			t.Errorf("Server() = %v", c.Server())
		}
	})
}

func TestBuildTLSConfigWithECH(t *testing.T) {
	c, err := NewClient(Option{Server: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	echList := []byte{0x00, 0x29, 0xfe, 0x0d}
	cfg, err := c.buildTLSConfigWithECH("example.com", echList)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.ServerName != "example.com" {
		t.Errorf("ServerName = %v", cfg.ServerName)
	}
	if !bytes.Equal(cfg.EncryptedClientHelloConfigList, echList) {
		t.Errorf("ECH config list mismatch: %x", cfg.EncryptedClientHelloConfigList)
	}
	if cfg.EncryptedClientHelloRejectionVerify == nil {
		t.Error("ECH rejection verifier is not set")
	}
	if cfg.EncryptedClientHelloRejectionVerify(tls.ConnectionState{}) == nil {
		t.Error("ECH rejection verifier should fail the handshake")
	}
	if cfg.RootCAs == nil {
		t.Error("system root pool not set")
	}

	t.Run("insecure", func(t *testing.T) {
		c, err := NewClient(Option{Server: "example.com:443", InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := c.buildTLSConfigWithECH("example.com", echList)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.InsecureSkipVerify {
			t.Error("InsecureSkipVerify not set")
		}
	})
}

func TestPrepareECHRetriesAndCancel(t *testing.T) {
	c, err := NewClient(Option{Server: "example.com:443", DNSServer: "https://127.0.0.1:1/dns-query"})
	if err != nil {
		t.Fatal(err)
	}
	if c.ECHReady() {
		t.Fatal("ECH should not be ready initially")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err = c.PrepareECH(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PrepareECH error = %v, want context.Canceled", err)
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Fatal("PrepareECH returned too early; retry loop not honored")
	}
	if c.ECHReady() {
		t.Fatal("ECH should still be empty after cancelled bootstrap")
	}
}

func TestGetECHListCopy(t *testing.T) {
	c, err := NewClient(Option{Server: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.getECHList(); err == nil {
		t.Fatal("expected error when ECH list is empty")
	}
	c.echMu.Lock()
	c.echList = []byte{1, 2, 3}
	c.echMu.Unlock()
	got, err := c.getECHList()
	if err != nil {
		t.Fatal(err)
	}
	got[0] = 9
	c.echMu.RLock()
	defer c.echMu.RUnlock()
	if c.echList[0] != 1 {
		t.Fatal("getECHList must return a copy")
	}
}

func TestDecodeBase64Std(t *testing.T) {
	got, err := decodeBase64Std("Zm9v")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "foo" {
		t.Fatalf("decodeBase64Std = %q", got)
	}
	if _, err := decodeBase64Std("!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDohPost(t *testing.T) {
	// Local DoH endpoint answering with a canned DNS response.
	canned := buildDNSResponse(t, []byte{0xfe, 0x0d}, true)
	srv := startHTTPHandler(t, func(w http.ResponseWriter, r map[string]any) {
		if r["path"] != "/dns-query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(canned)
	})
	defer srv.Close()

	client := &http.Client{}
	got, err := dohPost(context.Background(), client, srv.URL+"/dns-query", buildDNSQuery("cloudflare-ech.com", typeHTTPS))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, canned) {
		t.Fatalf("dohPost returned %d bytes, want the canned response", len(got))
	}
	if _, err := dohPost(context.Background(), client, srv.URL+"/missing", nil); err == nil {
		t.Fatal("expected error for wrong endpoint")
	}
}

func TestQueryDoHURLEncoding(t *testing.T) {
	// The GET form must carry the RFC 8484 "dns" query parameter.
	var gotPath, gotQuery string
	srv := startHTTPHandler(t, func(w http.ResponseWriter, r map[string]any) {
		gotPath = r["path"].(string)
		gotQuery = r["query"].(string)
		_, _ = w.Write([]byte{})
	})
	defer srv.Close()

	c, err := NewClient(Option{Server: "example.com:443", DNSServer: srv.URL + "/custom-path"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.queryHTTPSRecord(ctx, "cloudflare-ech.com", c.opt.DNSServer)

	if gotPath != "/custom-path" {
		t.Errorf("request path = %v, want /custom-path", gotPath)
	}
	if !strings.Contains(gotQuery, "dns=") {
		t.Errorf("query = %v, want dns parameter", gotQuery)
	}
}

func TestOptionLoggerDefault(t *testing.T) {
	c, err := NewClient(Option{Server: "example.com:443", Logger: logrus.New()})
	if err != nil {
		t.Fatal(err)
	}
	if c.log == nil || c.log.Logger == nil {
		t.Fatal("client logger not set")
	}
	if c.log.Data["scope"] != "echworkers" {
		t.Errorf("logger scope = %v, want echworkers", c.log.Data["scope"])
	}
	_ = reflect.TypeOf(c)
}
