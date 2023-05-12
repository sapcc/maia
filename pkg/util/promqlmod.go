package util

import (
	"reflect"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"golang.org/x/exp/slices"
)

// AddLabelConstraintToExpression enhances a PromQL expression to limit it to series matching a certain label.
// The function takes three parameters:
// 1. expression: The original PromQL expression.
// 2. key: The label key used to limit the series.
// 3. values: The label values that the series should match.
func AddLabelConstraintToExpression(expression, key string, values []string) (string, error) {
	// Parse the given PromQL expression
	exprNode, err := parser.ParseExpr(expression)
	if err != nil {
		return "", err
	}

	// Create a new label matcher based on the provided key and values.
	// The label matcher will be used to modify the syntax tree to include the new label constraint.
	matcher, err := makeLabelMatcher(key, values)
	if err != nil {
		return "", err
	}

	// Initialize a labelInjector with the created matcher.
	// The labelInjector will be used to traverse and modify the syntax tree.
	v := labelInjector{matcher: matcher}

	// Walk the PromQL expression tree and modify label matchers
	err = parser.Walk(v, exprNode, nil)
	if err != nil {
		return "", err
	}

	// Convert the modified syntax tree back into a string and return it.
	// The returned string is the original PromQL expression with the added label constraint.
	return exprNode.String(), nil
}

// AddLabelConstraintToSelector adds a label constraint to a metric selector
func AddLabelConstraintToSelector(metricSelector, key string, values []string) (string, error) {
	// Create a label matcher based on the provided key and values
	matcher, err := makeLabelMatcher(key, values)
	if err != nil {
		return "", err
	}

	// Parse the metric selector to obtain existing label matchers
	var labelMatchers []*labels.Matcher
	if metricSelector != "{}" {
		labelMatchers, err = parser.ParseMetricSelector(metricSelector)
	} else {
		labelMatchers = make([]*labels.Matcher, 0)
	}
	if err != nil {
		return "", err
	}

	// Combine the existing matchers with the new matcher
	combinedMatchers := append(labelMatchers, matcher)

	// Build the new metric selector string with the combined matchers
	var sb strings.Builder
	sb.WriteString("{")
	for i, m := range combinedMatchers {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(m.String())
	}
	sb.WriteString("}")

	return sb.String(), nil
}

// makeLabelMatcher creates a new labels.Matcher based on the provided key and values
func makeLabelMatcher(key string, values []string) (*labels.Matcher, error) {
	if len(values) == 1 {
		return labels.NewMatcher(labels.MatchEqual, key, values[0])
	}
	return labels.NewMatcher(labels.MatchRegexp, key, strings.Join(values, "|"))
}

// labelInjector is a parser.Visitor that enhances every reference to a metric (vector-selector)
// with an additional label constraint. This is used to restrict a query to metrics
// belonging to a single OpenStack tenant stored in label 'project_id'.
type labelInjector struct {
	matcher *labels.Matcher
}

// Visit modifies the label matchers of the visited parser.Node based on the labelInjector's matcher
func (v labelInjector) Visit(node parser.Node, path []parser.Node) (parser.Visitor, error) {
	switch n := node.(type) {
	case *parser.VectorSelector:
		if !slices.ContainsFunc(n.LabelMatchers, func(e *labels.Matcher) bool {
			return reflect.DeepEqual(e, v.matcher)
		}) {
			n.LabelMatchers = append(n.LabelMatchers, v.matcher)
		}
	}
	return v, nil
}
