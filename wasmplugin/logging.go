// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"encoding/json"

	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

const (
	blockedRequestLogEvent   = "coraza_waf_blocked_request"
	maxBlockedMatchedDataLen = 256
)

type blockedRequestLog struct {
	Event       string `json:"event"`
	Engine      string `json:"engine,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	RuleID      int    `json:"rule_id"`
	Severity    string `json:"severity,omitempty"`
	Category    string `json:"category,omitempty"`
	Phase       string `json:"phase"`
	Action      string `json:"action"`
	Status      int    `json:"status"`
	ClientIP    string `json:"client_ip,omitempty"`
	Method      string `json:"method,omitempty"`
	URI         string `json:"uri,omitempty"`
	MatchedData string `json:"matched_data,omitempty"`
}

func truncateMatchedData(data string) string {
	if len(data) <= maxBlockedMatchedDataLen {
		return data
	}
	return data[:maxBlockedMatchedDataLen]
}

func matchedRuleForInterruption(rules []ctypes.MatchedRule, ruleID int) ctypes.MatchedRule {
	for _, rule := range rules {
		if rule.Rule().ID() == ruleID {
			return rule
		}
	}
	return nil
}

func (ctx *httpContext) logBlockedRequest(phase interruptionPhase, interruption *ctypes.Interruption) {
	if !ctx.metricsMode.usesContractMetrics() || ctx.tx == nil || interruption == nil {
		return
	}

	statusCode := interruption.Status
	if statusCode == 0 {
		statusCode = defaultInterruptionStatusCode
	}

	entry := blockedRequestLog{
		Event:     blockedRequestLogEvent,
		Engine:    ctx.engine,
		Namespace: ctx.namespace,
		RuleID:    interruption.RuleID,
		Phase:     phase.String(),
		Action:    interruption.Action,
		Status:    statusCode,
		ClientIP:  ctx.clientIP,
		Method:    ctx.requestMethod,
		URI:       ctx.requestURI,
	}

	if matched := matchedRuleForInterruption(ctx.tx.MatchedRules(), interruption.RuleID); matched != nil {
		entry.Severity = contractSeverity(matched.Rule().Severity())
		entry.Category = categoryFromAttackTags(matched.Rule().Tags())
		if data := matched.Data(); data != "" {
			entry.MatchedData = truncateMatchedData(data)
		}
		if entry.ClientIP == "" {
			entry.ClientIP = matched.ClientIPAddress()
		}
	}
	setWAFAccessLogFilterState(interruption.RuleID, entry.Category)

	payload, err := json.Marshal(entry)
	if err != nil {
		proxywasm.LogWarnf("failed to marshal blocked request log: %v", err)
		return
	}
	// LogWarn so structured block events appear when Envoy proxyLogLevel is warning
	// (the default on Istio Gateway pods). LogInfo is filtered out in that case.
	proxywasm.LogWarn(string(payload))
}
