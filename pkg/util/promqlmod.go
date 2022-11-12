package util

import (
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

// AddLabelConstraintToExpression enhances a PromQL expression to limit it to series matching a certain label
func AddLabelConstraintToExpression(expression, key string, values []string) (string, error) {
	exprParsed, err := parser.ParseExpr(expression)
	if err != nil {
		return "", err
	}
	var matcher *labels.Matcher
	matcher, err = makeLabelMatcher(key, values)
	if err != nil {
		return "", err
	}

	// since to structure of the expression is not modified we can use a visitor, avoiding our own traversal code
	parser.Walk(labelInjector{matcher: matcher}, exprParsed, nil)

	return exprParsed.String(), nil
}

// AddLabelConstraintToSelector enhances a PromQL selector with an additional label selector
func AddLabelConstraintToSelector(metricSelector, key string, values []string) (string, error) {
	matcher, err := makeLabelMatcher(key, values)
	if err != nil {
		return "", err
	}

	var labelMatchers []*labels.Matcher
	if metricSelector != "{}" {
		labelMatchers, err = parser.ParseMetricSelector(metricSelector)
	}
	if err != nil {
		return "", err
	}
	return "{" + labelMatchers(append(labelMatchers, matcher)).String() + "}", nil //nolint:unconvert
}

// MakeLabelMatcher handles single label, and multilabel regex for child projects
func makeLabelMatcher(key string, values []string) (*labels.Matcher, error) {
	if len(values) == 1 {
		return labels.NewMatcher(labels.MatchEqual, key, values[0])
	}
	return labels.NewMatcher(labels.MatchRegexp, key, strings.Join(values, "|"))
}

// labelInjector enhances every reference to a metric (vector-selector) with an additional label-constraint
// We use this to restrict a query to metrics belonging to a single OpenStack tenants stored in label 'project_id'
type labelInjector struct {
	parser.Visitor
	matcher *labels.Matcher
}

// Visit does the actual modifications to PromQL expression nodes
func (v labelInjector) Visit(node parser.Node, path []parser.Node) (w parser.Visitor, err error) {

	switch node := node.(type) {
	case *parser.VectorSelector:
		labelMatchers := node.LabelMatchers
		labelMatchers = append(labelMatchers, v.matcher) //nolint:unconvert
	case *parser.MatrixSelector:
		labelMatchers := node.VectorSelector.(*parser.VectorSelector).LabelMatchers
		labelMatchers = append(labelMatchers, v.matcher) //nolint:unconvert
	}
	return v, nil
}
