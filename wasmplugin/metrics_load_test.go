// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"testing"

	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/assert"
)

func TestParseRuleOverrides(t *testing.T) {
	directives := `
SecRuleRemoveById 941100
SecRuleUpdateActionById 942150 "deny,status:403"
SecRuleUpdateTargetById 942200 "!ARGS:foo"
SecRuleRemoveByTag attack-sqli
`
	overrides := parseRuleOverrides(directives)
	assert.Len(t, overrides, 4)
}

func TestCountActiveRules(t *testing.T) {
	directives := `
SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,deny"
SecRule REQUEST_URI "@streq /foo" "id:102,phase:1,deny"
SecRuleRemoveById 102
`
	assert.Equal(t, 1, countActiveRules(directives))
}

func TestCategoryFromRuleTags(t *testing.T) {
	assert.Equal(t, "sqli", categoryFromAttackTags([]string{"attack-sqli", "OWASP_CRS"}))
	assert.Equal(t, "injection_php", categoryFromAttackTags([]string{"attack-injection-php", "OWASP_CRS"}))
	assert.Equal(t, "protocol", categoryFromAttackTags([]string{"attack-protocol"}))
	assert.Equal(t, "other", categoryFromAttackTags([]string{"OWASP_CRS"}))
}

func TestCategoryFromAttackTag(t *testing.T) {
	category, ok := categoryFromAttackTag("attack-xss")
	assert.True(t, ok)
	assert.Equal(t, "xss", category)

	_, ok = categoryFromAttackTag("not-an-attack-tag")
	assert.False(t, ok)
}

func TestAnomalyScoreFromMatchedRules(t *testing.T) {
	rules := []ctypes.MatchedRule{fakeMatchedRule{severity: ctypes.RuleSeverityCritical}}
	assert.Equal(t, uint64(5), anomalyScoreFromMatchedRules(rules))
}

type fakeMatchedRule struct {
	severity ctypes.RuleSeverity
	tags     []string
}

func (f fakeMatchedRule) Message() string                  { return "" }
func (f fakeMatchedRule) Data() string                     { return "" }
func (f fakeMatchedRule) URI() string                      { return "" }
func (f fakeMatchedRule) TransactionID() string            { return "" }
func (f fakeMatchedRule) Disruptive() bool                 { return true }
func (f fakeMatchedRule) ServerIPAddress() string          { return "" }
func (f fakeMatchedRule) ClientIPAddress() string          { return "" }
func (f fakeMatchedRule) MatchedDatas() []ctypes.MatchData { return nil }
func (f fakeMatchedRule) AuditLog() string                 { return "" }
func (f fakeMatchedRule) ErrorLog() string                 { return "" }
func (f fakeMatchedRule) Rule() ctypes.RuleMetadata        { return fakeRuleMetadata{f} }

type fakeRuleMetadata struct {
	fakeMatchedRule
}

func (f fakeRuleMetadata) ID() int                       { return 1 }
func (f fakeRuleMetadata) File() string                  { return "" }
func (f fakeRuleMetadata) Line() int                     { return 0 }
func (f fakeRuleMetadata) Revision() string              { return "" }
func (f fakeRuleMetadata) Severity() ctypes.RuleSeverity { return f.severity }
func (f fakeRuleMetadata) Version() string               { return "" }
func (f fakeRuleMetadata) Tags() []string                { return f.tags }
func (f fakeRuleMetadata) Maturity() int                 { return 0 }
func (f fakeRuleMetadata) Accuracy() int                 { return 0 }
func (f fakeRuleMetadata) Operator() string              { return "" }
func (f fakeRuleMetadata) Phase() ctypes.RulePhase       { return 0 }
func (f fakeRuleMetadata) Raw() string                   { return "" }
func (f fakeRuleMetadata) SecMark() string               { return "" }
