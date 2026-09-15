/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Lifecycle management of the optional "ech_tunnel" config section: the
 * standalone ech-workers tunnel client with its local SOCKS5/HTTP proxy
 * server. The controller survives reload generations and restarts the
 * server only when the relevant config actually changes.
 */

package cmd

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/echworkers"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

// echTunnelController owns the ech-workers standalone tunnel server.
type echTunnelController struct {
	mu     sync.Mutex
	client *echworkers.Client
	conf   *config.EchTunnel
	cancel context.CancelFunc
}

func newEchTunnelController() *echTunnelController {
	return &echTunnelController{}
}

// markedDirectDialer routes ech-workers connections through dae's direct
// dialer with the dae socket mark, so the eBPF data plane treats them as
// dae-originated traffic (pid_is_control_plane / dae_socket_mark) instead
// of re-capturing them — exactly like every other dae-internal
// connection. This keeps the tunnel from looping back through the proxy.
type markedDirectDialer struct {
	network string // pre-encoded magic network carrying mark/mptcp
}

func (d *markedDirectDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return direct.SymmetricDirect.DialContext(ctx, d.network, addr)
}

// newMarkedDirectDialer builds the marked direct dialer from global
// settings. The mark mirrors common.EffectiveSoMarkFromDae, which the
// control plane also programs into the eBPF parameter map.
func newMarkedDirectDialer(global *config.Global) *markedDirectDialer {
	mark, _ := common.ResolveSoMarkFromDae(global.SoMarkFromDae, global.SoMarkFromDaeSet)
	return &markedDirectDialer{
		network: common.MagicNetwork("tcp", mark, global.Mptcp),
	}
}

// refresh reconciles the running tunnel server with the wanted config:
//   - nil section or empty listen stops the server;
//   - a changed (or previously failed) section restarts it;
//   - an identical, healthy section is left untouched so reloads do not
//     needlessly re-bootstrap the ECH config.
func (c *echTunnelController) refresh(log *logrus.Logger, global *config.Global, want *config.EchTunnel) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if reflect.DeepEqual(c.conf, want) && (want == nil || want.Listen == "" || c.client != nil) {
		return
	}
	c.stopLocked(log)
	c.conf = want

	if want == nil {
		return
	}
	if want.Listen == "" {
		log.Warnln("[EchTunnel] section present but \"listen\" is empty; standalone proxy server disabled " +
			"(the tunnel is still available as echws:// node links)")
		return
	}

	var serverIPs []string
	if want.ServerIP != "" {
		serverIPs = []string{want.ServerIP}
	}
	client, err := echworkers.NewClient(echworkers.Option{
		Server:    want.Server,
		ServerIPs: serverIPs,
		Token:     want.Token,
		DNSServer: want.DNSServer,
		EchDomain: want.EchDomain,
		// Tunnel and DoH connections go through dae's direct dialer with
		// the dae socket mark, keeping them invisible to the eBPF data
		// plane (no self-capture, same as other dae-internal traffic).
		NextDialer: newMarkedDirectDialer(global),
	})
	if err != nil {
		log.WithError(err).Errorln("[EchTunnel] invalid ech_tunnel config")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.client = client
	c.cancel = cancel
	go func() {
		if err := client.StartProxyServer(ctx, want.Listen); err != nil && !errors.Is(err, context.Canceled) {
			log.WithError(err).Errorln("[EchTunnel] tunnel server stopped")
		}
	}()
}

// stop shuts the tunnel server down (process exit).
func (c *echTunnelController) stop(log *logrus.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conf = nil
	c.stopLocked(log)
}

func (c *echTunnelController) stopLocked(log *logrus.Logger) {
	if c.client != nil {
		c.client.StopProxyServer()
		c.client = nil
	}
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
}
