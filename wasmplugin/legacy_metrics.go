// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"fmt"
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

type wafMetrics struct {
	counters map[string]proxywasm.MetricCounter
}

func NewWAFMetrics() *wafMetrics {
	return &wafMetrics{
		counters: make(map[string]proxywasm.MetricCounter),
	}
}

func (m *wafMetrics) incrementCounter(fqn string) {
	if m == nil {
		return
	}
	counter, ok := m.counters[fqn]
	if !ok {
		counter = proxywasm.DefineCounterMetric(fqn)
		m.counters[fqn] = counter
	}
	counter.Increment(1)
}

func (m *wafMetrics) CountTX() {
	// Processed as waf_filter_tx_total in Prometheus when stats_tags are configured.
	m.incrementCounter("waf_filter.tx.total")
}

func (m *wafMetrics) CountTXInterruption(phase string, ruleID int, metricLabelsKV []string) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("waf_filter.tx.interruptions_ruleid=%d_phase=%s", ruleID, phase))

	for i := 0; i < len(metricLabelsKV); i += 2 {
		sb.WriteString(fmt.Sprintf("_%s=%s", metricLabelsKV[i], metricLabelsKV[i+1]))
	}

	m.incrementCounter(sb.String())
}
