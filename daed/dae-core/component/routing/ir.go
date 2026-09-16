/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"github.com/corevie/dae/config"
	"github.com/corevie/dae/pkg/config_parser"
)

// NormalizedProgram is the shared routing IR consumed by matcher builders.
// Rules are immutable after construction and may be lowered into userspace,
// DNS, or kernel-space backends.
type NormalizedProgram struct {
	Rules    []*config_parser.RoutingRule
	Fallback config.FunctionOrString
}
