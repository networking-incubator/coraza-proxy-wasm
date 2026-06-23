// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"strings"
	"unicode"
)

const (
	attackTagPrefix     = "attack-"
	categoryOther       = "other"
	categoryLabelMaxLen = 63
)

func (m *contractMetrics) categoryFromRuleTags(tags []string) string {
	if m == nil {
		return categoryOther
	}
	return categoryFromAttackTags(tags)
}

func categoryFromAttackTags(tags []string) string {
	for _, tag := range tags {
		if category, ok := categoryFromAttackTag(tag); ok {
			return category
		}
	}
	return categoryOther
}

func categoryFromAttackTag(tag string) (string, bool) {
	if !strings.HasPrefix(tag, attackTagPrefix) {
		return "", false
	}
	suffix := strings.TrimPrefix(tag, attackTagPrefix)
	if suffix == "" {
		return "", false
	}
	category := strings.ReplaceAll(suffix, "-", "_")
	if !isValidCategoryLabel(category) {
		return "", false
	}
	return category, true
}

func isValidCategoryLabel(category string) bool {
	if category == "" || len(category) > categoryLabelMaxLen {
		return false
	}
	for i, r := range category {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		case r == '_' && i > 0:
		default:
			return false
		}
	}
	return unicode.IsLetter(rune(category[0]))
}
