/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Outbound dialer for "echws://" links: dae-native access to the
 * ech-workers ECH websocket tunnel (component/echworkers).
 *
 * Link format:
 *
 *	echws://host:port[/path]?token=...&ip=...&dns=...&ech=...#name
 *
 *   - host:port[/path]: the wss tunnel server (port defaults to 443).
 *   - token: optional; sent as the websocket subprotocol for auth.
 *   - ip:    optional; pin the TCP connection to this IP (SNI stays host).
 *   - dns:   optional; DoH server used to fetch the ECH config
 *            (default dns.alidns.com/dns-query).
 *   - ech:   optional; domain queried for the ECH config
 *            (default cloudflare-ech.com).
 *   - name:  node display name (fragment).
 *
 * TCP is relayed through the tunnel; UDP is not supported by the tunnel
 * protocol and reports netproxy.UnsupportedTunnelTypeError, like other
 * TCP-only outbounds (e.g. http).
 */

package echws

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/component/echworkers"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func init() {
	D.FromLinkRegister("echws", NewECHWS)
}

// ECHWS is the link representation of an ech-workers tunnel node.
type ECHWS struct {
	Name          string   `json:"name"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Path          string   `json:"path"`
	ServerIPs     []string `json:"server_ips"`
	Token         string   `json:"token"`
	DNSServer     string   `json:"dns_server"`
	EchDomain     string   `json:"ech_domain"`
	AllowInsecure bool     `json:"allow_insecure"`
	Protocol      string   `json:"protocol"`
}

// parseServerIPList splits the ip= query parameter: a comma-separated list
// of IPs (or "ip:port" entries, whose port is stripped — cfMac nodes.json
// embeds Cloudflare edge candidates as ip:port).
func parseServerIPList(raw string) []string {
	if raw == "" {
		return nil
	}
	var ips []string
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(item); err == nil && net.ParseIP(host) != nil {
			item = host
		}
		if net.ParseIP(item) == nil {
			continue // tolerate junk entries instead of failing the node
		}
		ips = append(ips, item)
	}
	return ips
}

// NewECHWS is the FromLinkCreator of the "echws" scheme.
func NewECHWS(option *D.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *D.Property, error) {
	s, err := ParseECHWSURL(link)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", D.InvalidParameterErr, err)
	}
	return s.Dialer(nextDialer)
}

// ParseECHWSURL parses an echws:// link.
func ParseECHWSURL(link string) (data *ECHWS, err error) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "echws" {
		return nil, fmt.Errorf("invalid echws link: %v", err)
	}
	strPort := u.Port()
	if strPort == "" {
		strPort = "443"
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, fmt.Errorf("error when parsing port: %w", err)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	q := u.Query()
	getFirst := func(keys ...string) string {
		for _, key := range keys {
			if v := q.Get(key); v != "" {
				return v
			}
		}
		return ""
	}
	parseBool := func(keys ...string) bool {
		for _, key := range keys {
			if v := q.Get(key); v != "" {
				if b, err := strconv.ParseBool(v); err == nil {
					return b
				}
			}
		}
		return false
	}
	return &ECHWS{
		Name:          u.Fragment,
		Host:          u.Hostname(),
		Port:          port,
		Path:          path,
		ServerIPs:     parseServerIPList(getFirst("ip", "server_ip", "serverip")),
		Token:         getFirst("token"),
		DNSServer:     getFirst("dns", "doh"),
		EchDomain:     getFirst("ech", "echdomain", "ech_domain"),
		AllowInsecure: parseBool("allowInsecure", "allow_insecure", "allowinsecure", "skipVerify"),
		Protocol:      u.Scheme,
	}, nil
}

// Address returns "host:port" (without the path), the form dae uses for
// node host resolution and sticky-IP handling.
func (s *ECHWS) Address() string {
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

// Server returns the tunnel server in "host:port/path" form.
func (s *ECHWS) Server() string {
	return s.Address() + s.Path
}

// Dialer builds the netproxy dialer of this node.
func (s *ECHWS) Dialer(nextDialer netproxy.Dialer) (netproxy.Dialer, *D.Property, error) {
	client, err := echworkers.NewClient(echworkers.Option{
		Server:             s.Server(),
		ServerIPs:          s.ServerIPs,
		Token:              s.Token,
		DNSServer:          s.DNSServer,
		EchDomain:          s.EchDomain,
		InsecureSkipVerify: s.AllowInsecure,
		NextDialer:         nextDialer,
	})
	if err != nil {
		return nil, nil, err
	}
	name := s.Name
	if name == "" {
		name = s.Host
	}
	return &Dialer{client: client}, &D.Property{
		Name:     name,
		Address:  s.Address(),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}, nil
}

// URL renders the canonical link of this node.
func (s *ECHWS) URL() url.URL {
	u := url.URL{
		Scheme:   "echws",
		Host:     s.Address(),
		Path:     s.Path,
		Fragment: s.Name,
	}
	q := url.Values{}
	if s.Token != "" {
		q.Set("token", s.Token)
	}
	if len(s.ServerIPs) > 0 {
		q.Set("ip", strings.Join(s.ServerIPs, ","))
	}
	if s.DNSServer != "" {
		q.Set("dns", s.DNSServer)
	}
	if s.EchDomain != "" {
		q.Set("ech", s.EchDomain)
	}
	if s.AllowInsecure {
		q.Set("allowInsecure", "true")
	}
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return u
}

// ExportToURL returns the link as a string.
func (s *ECHWS) ExportToURL() string {
	u := s.URL()
	return u.String()
}

// Dialer adapts an echworkers.Client to the netproxy.Dialer interface.
type Dialer struct {
	client *echworkers.Client
}

// DialContext dials target through the ECH websocket tunnel. Only TCP is
// supported; UDP reports UnsupportedTunnelTypeError.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		if !d.client.ECHReady() {
			// Bootstrap the ECH config on first use; dial timeout bounds
			// the attempts so health checks fail fast.
			if err := d.client.RefreshECH(ctx); err != nil {
				return nil, fmt.Errorf("echws: ECH bootstrap failed: %w", err)
			}
		}
		tunnel, err := d.client.DialTunnel(ctx, addr, nil)
		if err != nil {
			return nil, fmt.Errorf("echws: dial %v: %w", addr, err)
		}
		return tunnel, nil
	case "udp":
		return nil, netproxy.UnsupportedTunnelTypeError
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
