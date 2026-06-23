// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestParseMetricsMode(t *testing.T) {
	mode, err := parseMetricsMode(gjson.Result{})
	require.NoError(t, err)
	assert.Equal(t, metricsModeLegacy, mode)

	mode, err = parseMetricsMode(gjson.Parse(`"contract"`))
	require.NoError(t, err)
	assert.Equal(t, metricsModeContract, mode)

	_, err = parseMetricsMode(gjson.Parse(`"unknown"`))
	require.Error(t, err)
}

func TestInitMetricsFromConfigLegacyDefault(t *testing.T) {
	cfg, err := parsePluginConfiguration([]byte(`{
		"directives_map": {"default": ["SecRuleEngine On"]},
		"default_directives": "default",
		"metric_labels": {"owner": "coraza", "identifier": "global"}
	}`), func(string) {})
	require.NoError(t, err)

	plugin := &corazaPlugin{}
	plugin.initMetricsFromConfig(cfg)

	assert.NotNil(t, plugin.legacyMetrics)
	assert.Nil(t, plugin.contractMetrics)
	assert.ElementsMatch(t, []string{"owner", "coraza", "identifier", "global"}, plugin.metricLabelsKV)
}

func TestInitMetricsFromConfigContract(t *testing.T) {
	cfg, err := parsePluginConfiguration([]byte(`{
		"directives_map": {"default": ["SecRuleEngine On"]},
		"default_directives": "default",
		"metrics_mode": "contract",
		"engine": "gw-waf",
		"namespace": "prod"
	}`), func(string) {})
	require.NoError(t, err)

	plugin := &corazaPlugin{}
	plugin.initMetricsFromConfig(cfg)

	assert.Nil(t, plugin.legacyMetrics)
	require.NotNil(t, plugin.contractMetrics)
	assert.True(t, plugin.contractMetrics.enabledMetrics())
}
