package util

import (
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

// AddLabelConstraintToExpression enhances a PromQL expression to limit it to series matching a certain label
func AddLabelConstraintToExpression(expression, key string, values []string) (string, error) {
	exprNode, err := parser.ParseExpr(expression)
	if err != nil {
		return "", err
	}
	matcher, err := makeLabelMatcher(key, values)
	if err != nil {
		return "", err
	}

	// since to structure of the expression is not modified we can use a visitor, avoiding our own traversal code
	parser.Walk(labelInjector{matcher: matcher}, exprNode)

	return exprNode.String(), nil
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
	} else {
		labelMatchers = make([]*labels.Matcher, 0)
	}
	if err != nil {
		return "", err
	}

	return "{" + labels.Labels(append(labelMatchers, matcher)).String() + "}", nil //nolint:unconvert
}

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
func (v labelInjector) Visit(node parser.Node) (w parser.Visitor) {
	switch node := node.(type) {
	case *parser.MatrixSelector:
		sel := node
		sel.LabelMatchers = labels.Labels(append(sel.LabelMatchers, v.matcher)) //nolint:unconvert
	case *parser.VectorSelector:
		sel := node
		sel.LabelMatchers = labels.Labels(append(sel.LabelMatchers, v.matcher)) //nolint:unconvert
	}

	return v
}
