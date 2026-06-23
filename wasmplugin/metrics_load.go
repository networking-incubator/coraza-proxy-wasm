// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"regexp"
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

type ruleOverride struct {
	ruleID string
	typ    string
}

var (
	secRuleRemoveByIDRe       = regexp.MustCompile(`(?i)SecRuleRemoveById\s+(\d+)`)
	secRuleUpdateActionByIDRe = regexp.MustCompile(`(?i)SecRuleUpdateActionById\s+(\d+)\b`)
	secRuleUpdateTargetByIDRe = regexp.MustCompile(`(?i)SecRuleUpdateTargetById\s+(\d+)\b`)
	secRuleRemoveByTagRe      = regexp.MustCompile(`(?i)SecRuleRemoveByTag\s+(\S+)`)
	secRuleIDRe               = regexp.MustCompile(`(?i)\bid\s*:\s*(\d+)\b`)
)

func parseRuleOverrides(directives string) []ruleOverride {
	var overrides []ruleOverride
	seen := make(map[string]struct{})

	add := func(ruleID, typ string) {
		key := ruleID + "|" + typ
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		overrides = append(overrides, ruleOverride{ruleID: ruleID, typ: typ})
	}

	for _, match := range secRuleRemoveByIDRe.FindAllStringSubmatch(directives, -1) {
		add(match[1], "disabled")
	}
	for _, match := range secRuleUpdateActionByIDRe.FindAllStringSubmatch(directives, -1) {
		add(match[1], "action_changed")
	}
	for _, match := range secRuleUpdateTargetByIDRe.FindAllStringSubmatch(directives, -1) {
		add(match[1], "threshold_changed")
	}
	for _, match := range secRuleRemoveByTagRe.FindAllStringSubmatch(directives, -1) {
		tag := strings.Trim(match[1], `"'`)
		add("tag:"+tag, "tag_removed")
	}

	return overrides
}

func countActiveRules(directives string) int {
	removed := make(map[string]struct{})
	for _, match := range secRuleRemoveByIDRe.FindAllStringSubmatch(directives, -1) {
		removed[match[1]] = struct{}{}
	}

	active := make(map[string]struct{})
	for _, match := range secRuleIDRe.FindAllStringSubmatch(directives, -1) {
		if _, isRemoved := removed[match[1]]; !isRemoved {
			active[match[1]] = struct{}{}
		}
	}
	return len(active)
}

func (m *contractMetrics) RecordLoadConfiguration(directives string) {
	if !m.enabledMetrics() {
		return
	}

	m.clearPreviousOverrideGauges()
	for _, override := range parseRuleOverrides(directives) {
		m.setGaugeValue("rule_overrides", [][2]string{
			{"rule_id", override.ruleID},
			{"type", override.typ},
		}, 1)
	}

	m.setPluginRuleCount(int64(countActiveRules(directives)))
}

func (m *contractMetrics) clearPreviousOverrideGauges() {
	for fqn := range m.lastOverrideGauges {
		if gauge, ok := m.gauges[fqn]; ok {
			if gauge.Value() > 0 {
				gauge.Add(-gauge.Value())
			}
		}
	}
	m.lastOverrideGauges = make(map[string]struct{})
}

func (m *contractMetrics) setPluginRuleCount(count int64) {
	fqn := buildStatName("plugin_rule_count", m.baseLabels())
	gauge := m.getOrCreateGauge(fqn)
	if m.lastPluginRuleCountGauge != "" && m.lastPluginRuleCountGauge != fqn {
		if old, ok := m.gauges[m.lastPluginRuleCountGauge]; ok && old.Value() > 0 {
			old.Add(-old.Value())
		}
	}
	delta := count - gauge.Value()
	if delta != 0 {
		gauge.Add(delta)
	}
	m.lastPluginRuleCountGauge = fqn
}

func (m *contractMetrics) setGaugeValue(metric string, labels [][2]string, value int64) {
	fqn := buildStatName(metric, append(m.baseLabels(), labels...))
	gauge := m.getOrCreateGauge(fqn)
	delta := value - gauge.Value()
	if delta != 0 {
		gauge.Add(delta)
	}
	m.lastOverrideGauges[fqn] = struct{}{}
}

func (m *contractMetrics) getOrCreateGauge(fqn string) proxywasm.MetricGauge {
	gauge, ok := m.gauges[fqn]
	if !ok {
		gauge = proxywasm.DefineGaugeMetric(fqn)
		m.gauges[fqn] = gauge
	}
	return gauge
}

// joinDirectives flattens a directives map into a single string for load-time parsing.
func joinDirectives(directivesMap DirectivesMap) string {
	var parts []string
	for _, directives := range directivesMap {
		parts = append(parts, directives...)
	}
	return strings.Join(parts, "\n")
}
