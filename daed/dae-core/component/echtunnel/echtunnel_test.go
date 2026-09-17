/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Reconciliation tests for the ech_tunnel controller. They cover the state
 * machine that decides whether the standalone proxy server is running -- the
 * part that used to live in cmd/ and was therefore unreachable from the
 * dashboard build. Starting a real tunnel is covered by the ech-workers tests.
 */

package echtunnel

import (
	"io"
	"testing"

	"github.com/corevie/dae/config"
	"github.com/sirupsen/logrus"
)

func quietLogger() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

func TestRefreshNilSectionIsNoop(t *testing.T) {
	c := New()
	c.Refresh(quietLogger(), &config.Global{}, nil)
	if c.client != nil || c.cancel != nil || c.conf != nil {
		t.Fatalf("controller started something without a section: %+v", c)
	}
}

// An empty listen keeps the tunnel available as echws:// node links but must
// not start the local SOCKS5/HTTP server.
func TestRefreshEmptyListenDoesNotStartServer(t *testing.T) {
	c := New()
	c.Refresh(quietLogger(), &config.Global{}, &config.EchTunnel{Server: "host:443", Listen: ""})
	if c.client != nil {
		t.Fatal("a server was started although listen is empty")
	}
	if c.conf == nil {
		t.Fatal("the wanted section should be remembered")
	}
}

// An invalid section (no server) must be reported and must not leave a
// half-started server behind.
func TestRefreshInvalidConfigDoesNotStart(t *testing.T) {
	c := New()
	c.Refresh(quietLogger(), &config.Global{}, &config.EchTunnel{Listen: "127.0.0.1:1080"})
	if c.client != nil || c.cancel != nil {
		t.Fatal("a server was started from an invalid ech_tunnel config")
	}
}

// Re-applying the identical section must not restart anything: reloads happen
// on every dashboard save and would otherwise re-bootstrap the ECH config.
func TestRefreshIdenticalConfigIsNoop(t *testing.T) {
	c := New()
	want := &config.EchTunnel{Server: "host:443", Listen: "127.0.0.1:1080"}
	c.Refresh(quietLogger(), &config.Global{}, want)
	before := c.conf

	// Same content, new pointer: DeepEqual must treat it as unchanged.
	c.Refresh(quietLogger(), &config.Global{}, &config.EchTunnel{Server: "host:443", Listen: "127.0.0.1:1080"})
	if c.conf != before {
		t.Fatal("an identical section replaced the stored config")
	}
	if !sameSection(c.conf, want) {
		t.Fatalf("stored config drifted: %+v", c.conf)
	}
}

// Withdrawing the section (or stopping) clears the stored config so a later
// reload with the same content is applied again.
func TestStopClearsConfig(t *testing.T) {
	c := New()
	c.Refresh(quietLogger(), &config.Global{}, &config.EchTunnel{Server: "host:443", Listen: "127.0.0.1:1080"})
	c.Stop(quietLogger())
	if c.conf != nil || c.client != nil || c.cancel != nil {
		t.Fatalf("stop left state behind: %+v", c)
	}
	// Refresh after a stop re-applies the section (no stale equality shortcut).
	c.Refresh(quietLogger(), &config.Global{}, &config.EchTunnel{Server: "host:443", Listen: ""})
	if c.conf == nil {
		t.Fatal("section was not re-applied after stop")
	}
}

func sameSection(a, b *config.EchTunnel) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Server == b.Server && a.Listen == b.Listen && a.Token == b.Token
}
