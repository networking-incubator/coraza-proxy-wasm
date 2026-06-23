// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"testing"

	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildStatName(t *testing.T) {
	name := buildStatName("requests_total", [][2]string{
		{"outcome", "pass"},
		{"engine", "gw-waf"},
		{"namespace", "prod"},
		{"driver_type", "wasm"},
	})
	assert.Equal(t, "coraza_waf.requests_total_driver_type=wasm_engine=gw-waf_namespace=prod_outcome=pass", name)
}

func TestNewContractMetricsDisabledWithoutLabels(t *testing.T) {
	var warned string
	m := newContractMetrics(contractMetricsConfig{}, func(format string, args ...interface{}) {
		warned = format
	})
	require.NotNil(t, m)
	assert.False(t, m.enabled)
	assert.Contains(t, warned, "coraza_waf metrics disabled")

	m.RecordRequestOutcome("pass")
	assert.Empty(t, m.counters)
}

func TestNewContractMetricsEnabled(t *testing.T) {
	m := newContractMetrics(contractMetricsConfig{
		Engine:    "gw-waf",
		Namespace: "prod",
	}, nil)
	require.True(t, m.enabled)
}

func TestTopNTrackerOverflow(t *testing.T) {
	tracker := newTopNTracker(2)

	assert.Equal(t, "1", tracker.labelRuleID(1))
	assert.Equal(t, "2", tracker.labelRuleID(2))
	assert.Equal(t, "other", tracker.labelRuleID(99))
}

func TestClassifyRequestOutcome(t *testing.T) {
	assert.Equal(t, "error", classifyRequestOutcome(nil, false, nil, true))
	assert.Equal(t, "redirect", classifyRequestOutcome(nil, true, &ctypes.Interruption{Action: "redirect"}, false))
	assert.Equal(t, "block", classifyRequestOutcome(nil, true, &ctypes.Interruption{Action: "deny"}, false))
}

func TestContractSeverity(t *testing.T) {
	assert.Equal(t, "CRITICAL", contractSeverity(ctypes.RuleSeverityCritical))
	assert.Equal(t, "ERROR", contractSeverity(ctypes.RuleSeverityError))
	assert.Equal(t, "INFO", contractSeverity(ctypes.RuleSeverityDebug))
}
