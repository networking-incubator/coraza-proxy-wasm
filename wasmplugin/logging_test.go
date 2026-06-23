// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTruncateMatchedData(t *testing.T) {
	short := "short payload"
	assert.Equal(t, short, truncateMatchedData(short))

	long := strings.Repeat("x", maxBlockedMatchedDataLen+10)
	truncated := truncateMatchedData(long)
	assert.Len(t, truncated, maxBlockedMatchedDataLen)
	assert.Equal(t, strings.Repeat("x", maxBlockedMatchedDataLen), truncated)
}

func TestBlockedRequestLogJSON(t *testing.T) {
	entry := blockedRequestLog{
		Event:       blockedRequestLogEvent,
		Engine:      "gw-waf",
		Namespace:   "prod",
		RuleID:      942100,
		Severity:    "CRITICAL",
		Category:    "sqli",
		Phase:       "http_request_headers",
		Action:      "deny",
		Status:      403,
		ClientIP:    "203.0.113.1",
		Method:      "GET",
		URI:         "/search?q=1+union+select",
		MatchedData: "union select",
	}

	payload, err := json.Marshal(entry)
	require.NoError(t, err)
	body := string(payload)
	assert.Contains(t, body, `"event":"coraza_waf_blocked_request"`)
	assert.Contains(t, body, `"rule_id":942100`)
}
