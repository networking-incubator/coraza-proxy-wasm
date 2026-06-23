// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
)

const (
	metricsModeLegacy   metricsMode = "legacy"
	metricsModeContract metricsMode = "contract"
)

type metricsMode string

func parseMetricsMode(value gjson.Result) (metricsMode, error) {
	if !value.Exists() {
		return metricsModeLegacy, nil
	}
	switch strings.ToLower(strings.TrimSpace(value.String())) {
	case string(metricsModeLegacy), "":
		return metricsModeLegacy, nil
	case string(metricsModeContract), "coraza_waf":
		return metricsModeContract, nil
	default:
		return "", fmt.Errorf("unsupported metrics_mode: %q (supported: %q, %q)", value.String(), metricsModeLegacy, metricsModeContract)
	}
}

func (m metricsMode) usesLegacyMetrics() bool {
	return m == metricsModeLegacy
}

func (m metricsMode) usesContractMetrics() bool {
	return m == metricsModeContract
}
