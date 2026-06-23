// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

func (m *contractMetrics) RecordBlockedCategories(rules []ctypes.MatchedRule, requestOutcome string) {
	if !m.enabledMetrics() {
		return
	}
	if requestOutcome != "block" && requestOutcome != "detect" && requestOutcome != "redirect" {
		return
	}

	seen := make(map[string]struct{})
	for _, rule := range rules {
		category := m.categoryFromRuleTags(rule.Rule().Tags())
		severity := contractSeverity(rule.Rule().Severity())
		key := category + "|" + severity
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		m.incrementCounter("blocked_requests_total", [][2]string{
			{"category", category},
			{"severity", severity},
		})
	}
}

// anomalyScoreFromMatchedRules approximates CRS inbound anomaly scoring using
// per-match severity weights when tx.inbound_anomaly_score is not exposed publicly.
func anomalyScoreFromMatchedRules(rules []ctypes.MatchedRule) uint64 {
	var score uint64
	for _, rule := range rules {
		score += uint64(severityAnomalyWeight(rule.Rule().Severity()))
	}
	return score
}

func severityAnomalyWeight(severity ctypes.RuleSeverity) int {
	switch severity {
	case ctypes.RuleSeverityEmergency, ctypes.RuleSeverityAlert, ctypes.RuleSeverityCritical:
		return 5
	case ctypes.RuleSeverityError:
		return 4
	case ctypes.RuleSeverityWarning:
		return 3
	case ctypes.RuleSeverityNotice:
		return 2
	case ctypes.RuleSeverityInfo, ctypes.RuleSeverityDebug:
		return 1
	default:
		return 0
	}
}

func (m *contractMetrics) RecordAnomalyScore(score uint64) {
	if !m.enabledMetrics() {
		return
	}
	fqn := buildStatName("request_anomaly_score", m.baseLabels())
	histogram, ok := m.histograms[fqn]
	if !ok {
		histogram = proxywasm.DefineHistogramMetric(fqn)
		m.histograms[fqn] = histogram
	}
	histogram.Record(score)
}
