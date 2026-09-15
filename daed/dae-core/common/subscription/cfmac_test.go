/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Tests of the cfMac nodes.json adapter and the gist:// subscription
 * source.
 */

package subscription

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

const sampleCfMacNodes = `{
  "activeNodeId" : "5EFDB413-05E6-426A-8F49-72434D633A77",
  "carrierDomainCountryMaps" : {
    "cmcc" : { "圣何塞" : ["sjc.cmcc.edu521.dpdns.org"] }
  },
  "modifiedAt" : 810983375.747516,
  "nodes" : [
    {
      "echDns" : "pe20ahrjvl.cloudflare-gateway.com/dns-query",
      "echDomain" : "cloudflare-ech.com",
      "id" : "0BB67D50-5D5C-40DF-B60F-ECD6AC47A61A",
      "ipv4" : true,
      "name" : "台湾-联通-0a49wo45@qabq.com",
      "prefIp" : "203.69.11.79,60.249.21.29",
      "token" : "e2659947",
      "wssAddr" : "withered-glitter-70fb.0a49wo45.workers.dev:443/?ip=162.158.241.217:443,172.69.221.158:443,162.158.241.18:443"
    },
    {
      "echDns" : "pe20ahrjvl.cloudflare-gateway.com/dns-query",
      "echDomain" : "cloudflare-ech.com",
      "id" : "6EB7CDFD-1BF0-4AE4-8A92-07277D080434",
      "ipv4" : true,
      "name" : "台湾-联通-17000093909@126.com",
      "prefIp" : "",
      "token" : "e2659947",
      "wssAddr" : "wss://hello-world-floral-mouse-81be.netclos.workers.dev:8443/custom-path"
    },
    {
      "id" : "broken",
      "name" : "坏节点",
      "wssAddr" : "not a valid addr"
    }
  ]
}`

func TestLooksLikeCfMacNodes(t *testing.T) {
	if !LooksLikeCfMacNodes([]byte(sampleCfMacNodes)) {
		t.Fatal("sample not recognized as cfMac nodes.json")
	}
	if LooksLikeCfMacNodes([]byte(`{"version":1,"servers":[]}`)) {
		t.Fatal("sip008 payload misrecognized as cfMac nodes.json")
	}
	if LooksLikeCfMacNodes([]byte(`not json`)) {
		t.Fatal("plain text misrecognized")
	}
}

func TestResolveSubscriptionAsCfMacNodes(t *testing.T) {
	nodes, err := ResolveSubscriptionAsCfMacNodes([]byte(sampleCfMacNodes))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %v (len %d), want 2 usable", nodes, len(nodes))
	}

	first, err := url.Parse(nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	if first.Scheme != "echws" {
		t.Errorf("scheme = %v", first.Scheme)
	}
	if first.Host != "withered-glitter-70fb.0a49wo45.workers.dev:443" {
		t.Errorf("host = %v", first.Host)
	}
	if first.Path != "/" {
		t.Errorf("path = %v, want / (query decoration stripped)", first.Path)
	}
	if first.Fragment != "台湾-联通-0a49wo45@qabq.com" {
		t.Errorf("fragment = %v", first.Fragment)
	}
	q := first.Query()
	if q.Get("token") != "e2659947" {
		t.Errorf("token = %v", q.Get("token"))
	}
	if q.Get("dns") != "pe20ahrjvl.cloudflare-gateway.com/dns-query" {
		t.Errorf("dns = %v", q.Get("dns"))
	}
	if q.Get("ech") != "cloudflare-ech.com" {
		t.Errorf("ech = %v", q.Get("ech"))
	}
	// prefIp first, then the edge candidates from wssAddr (deduped).
	wantIPs := "203.69.11.79,60.249.21.29,162.158.241.217,172.69.221.158,162.158.241.18"
	if q.Get("ip") != wantIPs {
		t.Errorf("ip = %v, want %v", q.Get("ip"), wantIPs)
	}

	// Second node: wss:// scheme stripped, custom port + path, no pin.
	second, err := url.Parse(nodes[1])
	if err != nil {
		t.Fatal(err)
	}
	if second.Host != "hello-world-floral-mouse-81be.netclos.workers.dev:8443" {
		t.Errorf("second host = %v", second.Host)
	}
	if second.Path != "/custom-path" {
		t.Errorf("second path = %v", second.Path)
	}
	if second.Query().Get("ip") != "" {
		t.Errorf("second ip = %v, want empty", second.Query().Get("ip"))
	}
}

func TestResolveSubscriptionCfMacViaFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nodes.json")
	if err := os.WriteFile(path, []byte(sampleCfMacNodes), 0600); err != nil {
		t.Fatal(err)
	}
	log := logrus.New()
	log.SetOutput(os.Stderr)
	tag, nodes, err := ResolveSubscription(log, &http.Client{}, dir, "ech_nodes:file://nodes.json")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "ech_nodes" {
		t.Errorf("tag = %v", tag)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %v", nodes)
	}
	if !strings.HasPrefix(nodes[0], "echws://") {
		t.Fatalf("node[0] = %v", nodes[0])
	}
}

func TestParseGistURL(t *testing.T) {
	tests := []struct {
		raw      string
		token    string
		gistID   string
		filename string
	}{
		{"gist://abc123", "", "abc123", ""},
		{"gist://abc123/nodes.json", "", "abc123", "nodes.json"},
		{"gist://tok123@abc123", "tok123", "abc123", ""},
		{"gist://tok123@abc123/nodes.json", "tok123", "abc123", "nodes.json"},
		{"gist-file://tok@abc123/nodes.json", "tok", "abc123", "nodes.json"},
	}
	for _, tt := range tests {
		u, err := url.Parse(tt.raw)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := ParseGistURL(u)
		if err != nil {
			t.Fatalf("ParseGistURL(%v): %v", tt.raw, err)
		}
		if ref.Token != tt.token || ref.GistID != tt.gistID || ref.Filename != tt.filename {
			t.Fatalf("ParseGistURL(%v) = %+v, want token=%v id=%v file=%v",
				tt.raw, ref, tt.token, tt.gistID, tt.filename)
		}
	}
	if _, err := ParseGistURL(urlMustParse("gist://")); err == nil {
		t.Fatal("expected error for empty gist id")
	}
}

func urlMustParse(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func TestResolveSubscriptionGist(t *testing.T) {
	// Mock the GitHub API and raw endpoints via an http client with a
	// custom transport rewriting requests to a local server.
	const apiGistBody = `{
	  "id": "abc123",
	  "files": {
	    "nodes.json": { "filename": "nodes.json", "raw_url": "http://raw.invalid/raw/nodes.json", "size": 100 },
	    "readme.md":  { "filename": "readme.md", "raw_url": "http://raw.invalid/raw/readme.md", "size": 10, "content": "hi" }
	  }
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gists/abc123":
			if r.Header.Get("Authorization") != "Bearer tok123" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(apiGistBody))
		case "/raw/nodes.json":
			_, _ = w.Write([]byte(sampleCfMacNodes))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: rewriteTransport{base: srv.URL}}

	log := logrus.New()
	log.SetOutput(os.Stderr)
	tag, nodes, err := ResolveSubscription(log, client, t.TempDir(),
		"ech_nodes:gist://tok123@abc123/nodes.json")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "ech_nodes" {
		t.Errorf("tag = %v", tag)
	}
	if len(nodes) != 2 || !strings.HasPrefix(nodes[0], "echws://") {
		t.Fatalf("nodes = %v", nodes)
	}
}

// rewriteTransport redirects every request to a local test server.
type rewriteTransport struct {
	base string
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(t.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}
