/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * DoH (DNS over HTTPS) helpers of the ech-workers tunnel client.
 *
 * This file ports the manual DNS wire-format codec of the original
 * workers.go: it builds a HTTPS (type 65) query, sends it to a DoH server
 * using the RFC 8484 "dns" query parameter, and extracts the ECH
 * (SvcParam key 5) config from the answer.
 */

package echworkers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// dohQueryTimeout is the timeout of a single DoH request.
const dohQueryTimeout = 10 * time.Second

// decodeBase64Std is a small helper around base64.StdEncoding.DecodeString.
func decodeBase64Std(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// queryHTTPSRecord queries the HTTPS (type 65) record of domain via the
// given DoH server, returning the base64 ECH config list (or "" if the
// answer carries no ECH parameter).
func (c *Client) queryHTTPSRecord(ctx context.Context, domain, server string) (string, error) {
	dohURL := server
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dohURL, nil)
	if err != nil {
		return "", fmt.Errorf("invalid DoH URL: %w", err)
	}
	client := &http.Client{Transport: c.dohTransport(), Timeout: dohQueryTimeout}
	return queryDoH(ctx, client, req, domain, dohURL)
}

// dohTransport returns the HTTP transport for DoH bootstrap queries. When
// a NextDialer is configured, its TCP connections flow through dae's
// regular dialer stack and carry the dae socket mark, so the eBPF data
// plane treats them as dae-originated traffic instead of re-capturing
// them (same as every other dae-internal connection).
func (c *Client) dohTransport() *http.Transport {
	transport := &http.Transport{}
	if c.opt.NextDialer != nil {
		nextDialer := c.opt.NextDialer
		serverIP := c.pickServerIP()
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if serverIP != "" {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				addr = net.JoinHostPort(serverIP, port)
			}
			conn, err := nextDialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{
				Conn:  conn,
				LAddr: fakeTCPAddr("127.0.0.1:0"),
				RAddr: fakeTCPAddr(addr),
			}, nil
		}
	}
	return transport
}

// queryDoH issues a GET DoH request with the RFC 8484 "dns" query
// parameter and returns the base64 ECH config list from the first HTTPS
// record that carries one.
func queryDoH(ctx context.Context, client *http.Client, req *http.Request, domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("invalid DoH URL: %w", err)
	}

	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

	q := u.Query()
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()
	req.URL = u
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH server returned error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read DoH response: %w", err)
	}
	return parseDNSResponse(body)
}

// dohPost sends a raw DNS message to a DoH endpoint via POST
// (application/dns-message), returning the raw DNS response.
func dohPost(ctx context.Context, client *http.Client, dohURL string, dnsQuery []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned error: %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// newECHHTTPTransport builds an HTTP transport carrying an ECH-enabled TLS
// config. When serverIP is set, all connections are pinned to that IP.
func newECHHTTPTransport(tlsCfg *tls.Config, serverIP string) *http.Transport {
	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	if serverIP != "" {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var d net.Dialer
			d.Timeout = dialTimeout
			return d.DialContext(ctx, network, net.JoinHostPort(serverIP, port))
		}
	}
	return transport
}

// buildDNSQuery builds the wire format of a recursive DNS query for
// domain with the given qtype. Only one question is supported, which is
// all the ECH bootstrap needs.
func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	// Header: id=1, RD=1, QDCOUNT=1.
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

// parseDNSResponse walks the answer section of a DNS response and returns
// the base64 ECH config list of the first HTTPS record that carries one.
func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("response too short")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("no answer records")
	}

	// Skip the question section.
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5

	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			// Compressed name.
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

// parseHTTPSRecord extracts the base64-encoded ECH config list
// (SvcParam key 5) from an HTTPS (SVCB) record rdata.
func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// Skip SvcPriority (2 bytes).
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		// Root name ".".
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}
