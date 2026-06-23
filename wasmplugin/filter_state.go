// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"strconv"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// Filter state keys for Envoy access logs (%FILTER_STATE(wasm.<key>)%).
// See: https://github.com/envoyproxy/envoy/issues/38738
const (
	filterStateWAFBlocked  = "coraza_waf_blocked"
	filterStateWAFRuleID   = "coraza_waf_rule_id"
	filterStateWAFCategory = "coraza_waf_category"
)

func setWAFAccessLogFilterState(ruleID int, category string) {
	_ = proxywasm.SetProperty([]string{"filter_state", filterStateWAFBlocked}, []byte("true"))
	_ = proxywasm.SetProperty([]string{"filter_state", filterStateWAFRuleID}, []byte(strconv.Itoa(ruleID)))
	if category != "" {
		_ = proxywasm.SetProperty([]string{"filter_state", filterStateWAFCategory}, []byte(category))
	}
}
