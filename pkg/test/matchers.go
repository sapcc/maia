// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"

	"go.uber.org/mock/gomock"
)

// ContextMatcher is a custom matcher for contexts
type ContextMatcher struct{}

func (m ContextMatcher) Matches(x interface{}) bool {
	_, ok := x.(context.Context)
	return ok
}

func (m ContextMatcher) String() string {
	return "is a context.Context"
}

// MatchContext returns a matcher for any context.Context
func MatchContext() gomock.Matcher {
	return ContextMatcher{}
}
