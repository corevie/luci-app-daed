/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * cfMac nodes.json adapter: converts the node library of the cfMac
 * (CloudPulse) ECH tunnel clients into dae "echws://" node links.
 *
 * Documented format (see /Users/mer/Downloads/代理/cfMac/nodes.json):
 *
 *	{
 *	  "activeNodeId": "<uuid>",
 *	  "carrierDomainCountryMaps": { ... },   // informational, ignored
 *	  "modifiedAt": 810983375.747516,        // informational, ignored
 *	  "nodes": [
 *	    {
 *	      "id": "<uuid>",
 *	      "name": "台湾-联通-xxx@example.com",
 *	      "wssAddr": "xxx.workers.dev:443/?ip=1.1.1.1:443,2.2.2.2:443",
 *	      "prefIp": "203.69.11.79,60.249.21.29",   // measured preferred IPs
 *	      "echDns": "pe20ahrjvl.cloudflare-gateway.com/dns-query",
 *	      "echDomain": "cloudflare-ech.com",
 *	      "token": "e2659947",
 *	      "ipv4": true
 *	    }
 *	  ]
 *	}
 *
 * Mapping to echws links:
 *
 *	wssAddr  -> host:port/path (the embedded ?ip= list is decorative; its
 *	            entries are kept as fail-over candidates after prefIp)
 *	prefIp   -> ip= (preferred, ordered first)
 *	wssAddr ?ip= -> appended to ip= after dedup (ports stripped)
 *	echDns   -> dns=
 *	echDomain-> ech=
 *	token    -> token=
 *	name     -> fragment (node display name)
 */

package subscription

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// cfMacFile is the top-level structure of nodes.json.
type cfMacFile struct {
	ActiveNodeId string          `json:"activeNodeId"`
	Nodes        json.RawMessage `json:"nodes"`
}

// cfMacNode is one tunnel node entry.
type cfMacNode struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	WssAddr   string `json:"wssAddr"`
	PrefIp    string `json:"prefIp"`
	EchDns    string `json:"echDns"`
	EchDomain string `json:"echDomain"`
	Token     string `json:"token"`
	Ipv4      bool   `json:"ipv4"`
}

// LooksLikeCfMacNodes reports whether b is a cfMac nodes.json payload.
func LooksLikeCfMacNodes(b []byte) bool {
	var f cfMacFile
	if err := json.Unmarshal(b, &f); err != nil {
		return false
	}
	return len(f.Nodes) > 0 && strings.HasPrefix(strings.TrimSpace(string(f.Nodes)), "[")
}

// ResolveSubscriptionAsCfMacNodes converts a cfMac nodes.json payload into
// echws:// node links. Nodes that cannot be parsed are skipped (with the
// error reported when nothing usable remains).
func ResolveSubscriptionAsCfMacNodes(b []byte) (nodes []string, err error) {
	var f cfMacFile
	if err = json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cfMac nodes.json: %w", err)
	}
	var list []cfMacNode
	if err = json.Unmarshal(f.Nodes, &list); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cfMac nodes list: %w", err)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("cfMac nodes.json contains no nodes")
	}
	for _, node := range list {
		link, e := cfMacNodeToLink(node)
		if e != nil {
			continue
		}
		nodes = append(nodes, link)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no usable echws node in cfMac nodes.json")
	}
	return nodes, nil
}

// cfMacNodeToLink converts one cfMac node entry into an echws:// link.
func cfMacNodeToLink(node cfMacNode) (string, error) {
	wssAddr := strings.TrimSpace(node.WssAddr)
	if wssAddr == "" {
		return "", fmt.Errorf("node %q has no wssAddr", node.Name)
	}
	// Strip an optional scheme ("wss://").
	if idx := strings.Index(wssAddr, "://"); idx >= 0 {
		wssAddr = wssAddr[idx+3:]
	}
	// Split host:port from path (path includes any "?ip=..." decoration).
	hostPort, path := wssAddr, "/"
	if idx := strings.Index(wssAddr, "/"); idx >= 0 {
		hostPort, path = wssAddr[:idx], wssAddr[idx:]
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", fmt.Errorf("node %q has invalid wssAddr %q: %w", node.Name, node.WssAddr, err)
	}
	if _, e := strconv.Atoi(port); e != nil {
		return "", fmt.Errorf("node %q has non-numeric port in %q", node.Name, node.WssAddr)
	}
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i] // the ?ip= decoration is not a real route
	}
	if path == "" {
		path = "/"
	}

	// Candidate IPs: measured preferred IPs first, then the edge list
	// embedded in wssAddr (both tolerate "ip:port" entries).
	var ips []string
	seen := map[string]struct{}{}
	addIP := func(raw string) {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if h, _, e := net.SplitHostPort(item); e == nil {
				item = h
			}
			if net.ParseIP(item) == nil {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			ips = append(ips, item)
		}
	}
	addIP(node.PrefIp)
	if rawQuery := queryParamFromWssAddr(node.WssAddr, "ip"); rawQuery != "" {
		addIP(rawQuery)
	}

	u := url.URL{
		Scheme:   "echws",
		Host:     net.JoinHostPort(host, port),
		Path:     path,
		Fragment: node.Name,
	}
	q := url.Values{}
	if node.Token != "" {
		q.Set("token", node.Token)
	}
	if node.EchDns != "" {
		q.Set("dns", node.EchDns)
	}
	if node.EchDomain != "" {
		q.Set("ech", node.EchDomain)
	}
	if len(ips) > 0 {
		q.Set("ip", strings.Join(ips, ","))
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

// queryParamFromWssAddr extracts a query parameter embedded in the "?..."
// decoration of a cfMac wssAddr.
func queryParamFromWssAddr(wssAddr, key string) string {
	idx := strings.Index(wssAddr, "?")
	if idx < 0 {
		return ""
	}
	q, err := url.ParseQuery(wssAddr[idx+1:])
	if err != nil {
		return ""
	}
	return q.Get(key)
}
