// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"sort"
	"strconv"
	"strings"

	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

const (
	defaultDriverType      = "wasm"
	defaultRuleHitsTopN    = 200
	metricsDisabledMessage = "coraza_waf metrics disabled: pluginConfig must include non-empty engine and namespace labels; WAF will continue without dataplane metrics"
)

type warnLogger func(string, ...interface{})

// contractMetrics emits coraza_waf_* Envoy stats for the operator dataplane contract.
// Labels are encoded into stat names and extracted by Envoy stats_tags regexes.
type contractMetrics struct {
	enabled    bool
	engine     string
	namespace  string
	driverType string

	counters   map[string]proxywasm.MetricCounter
	histograms map[string]proxywasm.MetricHistogram
	gauges     map[string]proxywasm.MetricGauge

	ruleHitsTopN *topNTracker

	lastOverrideGauges       map[string]struct{}
	lastPluginRuleCountGauge string
}

type contractMetricsConfig struct {
	Engine     string
	Namespace  string
	DriverType string
	TopN       int
}

func newContractMetrics(cfg contractMetricsConfig, logWarn warnLogger) *contractMetrics {
	driverType := cfg.DriverType
	if driverType == "" {
		driverType = defaultDriverType
	}

	topN := cfg.TopN
	if topN <= 0 {
		topN = defaultRuleHitsTopN
	}

	m := &contractMetrics{
		driverType:         driverType,
		counters:           make(map[string]proxywasm.MetricCounter),
		histograms:         make(map[string]proxywasm.MetricHistogram),
		gauges:             make(map[string]proxywasm.MetricGauge),
		ruleHitsTopN:       newTopNTracker(topN),
		lastOverrideGauges: make(map[string]struct{}),
	}

	if strings.TrimSpace(cfg.Engine) == "" || strings.TrimSpace(cfg.Namespace) == "" {
		if logWarn != nil {
			logWarn(metricsDisabledMessage)
		}
		return m
	}

	m.enabled = true
	m.engine = cfg.Engine
	m.namespace = cfg.Namespace
	return m
}

func (m *contractMetrics) enabledMetrics() bool {
	return m != nil && m.enabled
}

func (m *contractMetrics) resetOnReload() {
	if !m.enabledMetrics() {
		return
	}
	m.ruleHitsTopN.reset()
	m.clearPreviousOverrideGauges()
}

func (m *contractMetrics) baseLabels() [][2]string {
	return [][2]string{
		{"engine", m.engine},
		{"namespace", m.namespace},
		{"driver_type", m.driverType},
	}
}

func buildStatName(metric string, labels [][2]string) string {
	sort.Slice(labels, func(i, j int) bool {
		return labels[i][0] < labels[j][0]
	})

	var sb strings.Builder
	sb.WriteString("coraza_waf.")
	sb.WriteString(metric)
	for _, label := range labels {
		sb.WriteString("_")
		sb.WriteString(label[0])
		sb.WriteByte('=')
		sb.WriteString(label[1])
	}
	return sb.String()
}

func (m *contractMetrics) incrementCounter(metric string, labels [][2]string) {
	fqn := buildStatName(metric, append(m.baseLabels(), labels...))
	counter, ok := m.counters[fqn]
	if !ok {
		counter = proxywasm.DefineCounterMetric(fqn)
		m.counters[fqn] = counter
	}
	counter.Increment(1)
}

func (m *contractMetrics) RecordRequestOutcome(outcome string) {
	if !m.enabledMetrics() {
		return
	}
	m.incrementCounter("requests_total", [][2]string{{"outcome", outcome}})
}

func (m *contractMetrics) RecordRuleHit(ruleID int, severity, outcome string) {
	if !m.enabledMetrics() {
		return
	}
	labelRuleID := m.ruleHitsTopN.labelRuleID(ruleID)
	m.incrementCounter("rule_hits_total", [][2]string{
		{"rule_id", labelRuleID},
		{"severity", severity},
		{"outcome", outcome},
	})
}

func (m *contractMetrics) RecordPluginLoad(success bool) {
	if !m.enabledMetrics() {
		return
	}
	status := "failure"
	if success {
		status = "success"
	}
	m.incrementCounter("plugin_loads_total", [][2]string{{"status", status}})
}

func (m *contractMetrics) RecordMatchedRules(rules []ctypes.MatchedRule, requestOutcome string) {
	if !m.enabledMetrics() {
		return
	}
	for _, rule := range rules {
		m.RecordRuleHit(rule.Rule().ID(), contractSeverity(rule.Rule().Severity()), ruleHitOutcome(rule, requestOutcome))
	}
}

type topNTracker struct {
	limit  int
	counts map[int]uint64
	top    map[int]struct{}
}

func newTopNTracker(limit int) *topNTracker {
	return &topNTracker{
		limit:  limit,
		counts: make(map[int]uint64),
		top:    make(map[int]struct{}),
	}
}

func (t *topNTracker) reset() {
	t.counts = make(map[int]uint64)
	t.top = make(map[int]struct{})
}

func (t *topNTracker) labelRuleID(ruleID int) string {
	if ruleID <= 0 {
		return "other"
	}

	t.counts[ruleID]++
	if _, ok := t.top[ruleID]; ok {
		return strconv.Itoa(ruleID)
	}
	if len(t.top) < t.limit {
		t.top[ruleID] = struct{}{}
		return strconv.Itoa(ruleID)
	}

	t.recomputeTop()
	if _, ok := t.top[ruleID]; ok {
		return strconv.Itoa(ruleID)
	}
	return "other"
}

func (t *topNTracker) recomputeTop() {
	type ruleCount struct {
		id    int
		count uint64
	}
	ranked := make([]ruleCount, 0, len(t.counts))
	for id, count := range t.counts {
		ranked = append(ranked, ruleCount{id: id, count: count})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].count == ranked[j].count {
			return ranked[i].id < ranked[j].id
		}
		return ranked[i].count > ranked[j].count
	})

	t.top = make(map[int]struct{}, t.limit)
	for i := 0; i < len(ranked) && i < t.limit; i++ {
		t.top[ranked[i].id] = struct{}{}
	}
}

func contractSeverity(severity ctypes.RuleSeverity) string {
	switch severity {
	case ctypes.RuleSeverityEmergency, ctypes.RuleSeverityAlert, ctypes.RuleSeverityCritical:
		return "CRITICAL"
	case ctypes.RuleSeverityError:
		return "ERROR"
	case ctypes.RuleSeverityWarning:
		return "WARNING"
	case ctypes.RuleSeverityNotice:
		return "NOTICE"
	case ctypes.RuleSeverityInfo, ctypes.RuleSeverityDebug:
		return "INFO"
	default:
		return "INFO"
	}
}

func ruleHitOutcome(rule ctypes.MatchedRule, requestOutcome string) string {
	if !rule.Disruptive() {
		if requestOutcome == "pass" {
			return "pass"
		}
		return "detect"
	}
	switch requestOutcome {
	case "block", "redirect":
		return "block"
	default:
		return "detect"
	}
}

func classifyRequestOutcome(tx ctypes.Transaction, interrupted bool, interruption *ctypes.Interruption, evalError bool) string {
	if evalError {
		return "error"
	}
	if interrupted && interruption != nil {
		switch strings.ToLower(interruption.Action) {
		case "redirect":
			return "redirect"
		case "deny", "drop", "block":
			return "block"
		default:
			return "block"
		}
	}

	for _, rule := range tx.MatchedRules() {
		if !rule.Disruptive() {
			return "detect"
		}
	}
	return "pass"
}
