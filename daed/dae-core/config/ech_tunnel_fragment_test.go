/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Tests for the ech_tunnel drop-in fragment path used by the dashboard build:
 * the section written by the LuCI page must decode exactly like an inline one.
 */

package config

import (
	"reflect"
	"testing"

	"github.com/corevie/dae/pkg/config_parser"
)

func parseFragmentSections(t *testing.T, text string) []*config_parser.Section {
	t.Helper()
	sections, err := config_parser.Parse(text)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return sections
}

func TestParseEchTunnelSectionsAbsent(t *testing.T) {
	sections := parseFragmentSections(t, "global {}\nrouting {}\nnode {}\n")
	got, err := ParseEchTunnelSections(sections)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("EchTunnel = %+v, want nil", got)
	}
}

func TestParseEchTunnelSectionsFull(t *testing.T) {
	// Mirror of the runfile the LuCI page writes.
	sections := parseFragmentSections(t, `
global {}
routing {}
ech_tunnel {
    listen: '127.0.0.1:1080'
    server: 'your-worker.workers.dev:443/tunnel'
    ip: '104.21.16.1'
    token: 'e2659947'
    dns: 'dns.alidns.com/dns-query'
    ech_domain: 'cloudflare-ech.com'
}
`)
	got, err := ParseEchTunnelSections(sections)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := &EchTunnel{
		Listen:    "127.0.0.1:1080",
		Server:    "your-worker.workers.dev:443/tunnel",
		ServerIP:  "104.21.16.1",
		Token:     "e2659947",
		DNSServer: "dns.alidns.com/dns-query",
		EchDomain: "cloudflare-ech.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EchTunnel = %+v, want %+v", got, want)
	}
}

func TestParseEchTunnelSectionsOptionalFieldsOmitted(t *testing.T) {
	sections := parseFragmentSections(t, "ech_tunnel {\n    listen: '127.0.0.1:1080'\n    server: 'host:443'\n}\n")
	got, err := ParseEchTunnelSections(sections)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Server != "host:443" || got.ServerIP != "" || got.Token != "" {
		t.Fatalf("EchTunnel = %+v", got)
	}
}

func TestParseEchTunnelSectionsServerRequired(t *testing.T) {
	sections := parseFragmentSections(t, "ech_tunnel {\n    listen: '127.0.0.1:1080'\n}\n")
	if _, err := ParseEchTunnelSections(sections); err == nil {
		t.Fatal("expected an error when server is missing")
	}
}

func TestParseEchTunnelSectionsDuplicate(t *testing.T) {
	sections := parseFragmentSections(t, "ech_tunnel { server: 'a:443' }\nech_tunnel { server: 'b:443' }\n")
	if _, err := ParseEchTunnelSections(sections); err == nil {
		t.Fatal("expected an error for duplicate ech_tunnel sections")
	}
}

func TestParseEchTunnelSectionsUnknownKey(t *testing.T) {
	sections := parseFragmentSections(t, "ech_tunnel {\n    server: 'host:443'\n    nonsense: 'x'\n}\n")
	if _, err := ParseEchTunnelSections(sections); err == nil {
		t.Fatal("expected an error for an unknown key")
	}
}

// The fragment path must not be a way to smuggle other sections: only
// ech_tunnel is decoded, everything else is ignored.
func TestParseEchTunnelSectionsIgnoresOtherSections(t *testing.T) {
	sections := parseFragmentSections(t, `
global { log_level: 'debug' }
routing { fallback: direct }
subscription { sub: 'https://example.com/sub' }
ech_tunnel {
    listen: '127.0.0.1:1080'
    server: 'host:443'
}
`)
	got, err := ParseEchTunnelSections(sections)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Server != "host:443" {
		t.Fatalf("EchTunnel = %+v", got)
	}
}
