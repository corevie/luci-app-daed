/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"

	"github.com/corevie/dae/pkg/config_parser"
)

// ParseEchTunnelSections decodes the optional "ech_tunnel" section out of
// sections that are NOT a complete dae config -- for example a runfile fragment
// written by the LuCI "ECH Tunnel" page.
//
// The dashboard (dae-wing) build keeps globals, DNS, routing, nodes and
// subscriptions in its database and therefore never parses a full runfile;
// this is what lets the ech_tunnel section reach the core there. The full
// config parser handles the same section when the standalone daemon reads a
// runfile directly, and both paths share the decoder below, so a fragment
// behaves exactly like an inline section.
//
// Returns nil, nil when no ech_tunnel section is present.
func ParseEchTunnelSections(sections []*config_parser.Section) (*EchTunnel, error) {
	var found *config_parser.Section
	for _, section := range sections {
		if section == nil || section.Name != "ech_tunnel" {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("more than one ech_tunnel section provided")
		}
		found = section
	}
	if found == nil {
		return nil, nil
	}

	holder := &Config{}
	if err := decodeConfigSection(holder, "ech_tunnel", found); err != nil {
		return nil, fmt.Errorf("failed to parse \"ech_tunnel\": %w", err)
	}
	// Same validation the full config applies (server is mandatory).
	if err := patchEchTunnel(holder); err != nil {
		return nil, err
	}
	return holder.EchTunnel, nil
}
