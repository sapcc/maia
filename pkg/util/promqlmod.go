package util

import (
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage/metric"
	"strings"
)

// AddLabelConstraintToExpression enhances a PromQL expression to limit it to series matching a certain label
func AddLabelConstraintToExpression(expression string, key string, values []string) (string, error) {
	exprNode, err := promql.ParseExpr(expression)
	if err != nil {
		return "", err
	}
	matcher, err := makeLabelMatcher(key, values)
	if err != nil {
		return "", err
	}

	// since to structure of the expression is not modified we can use a visitor, avoiding our own traversal code
	promql.Walk(labelInjector{matcher: matcher}, exprNode)

	return exprNode.String(), nil
}

// AddLabelConstraintToSelector enhances a PromQL selector with an additional label selector
func AddLabelConstraintToSelector(metricSelector string, key string, values []string) (string, error) {
	matcher, err := makeLabelMatcher(key, values)
	if err != nil {
		return "", err
	}

	var labelMatchers metric.LabelMatchers
	if metricSelector != "{}" {
		labelMatchers, err = promql.ParseMetricSelector(metricSelector)
	} else {
		labelMatchers = make(metric.LabelMatchers, 0)
	}
	if err != nil {
		return "", err
	}
	return "{" + metric.LabelMatchers(append(labelMatchers, matcher)).String() + "}", nil
}

func makeLabelMatcher(key string, values []string) (*metric.LabelMatcher, error) {
	if len(values) == 1 {
		return metric.NewLabelMatcher(metric.Equal, model.LabelName(key), model.LabelValue(values[0]))
	}
	return metric.NewLabelMatcher(metric.RegexMatch, model.LabelName(key), model.LabelValue(strings.Join(values, "|")))
}

// labelInjector enhances every reference to a metric (vector-selector) with an additional label-constraint
// We use this to restrict a query to metrics belonging to a single OpenStack tenants stored in label 'project_id'
type labelInjector struct {
	promql.Visitor
	matcher *metric.LabelMatcher
}

// Visit does the actual modifications to PromQL expression nodes
func (v labelInjector) Visit(node promql.Node) (w promql.Visitor) {
	switch node.(type) {
	case *promql.MatrixSelector:
		sel := node.(*promql.MatrixSelector)
		sel.LabelMatchers = metric.LabelMatchers(append(sel.LabelMatchers, v.matcher))
	case *promql.VectorSelector:
		sel := node.(*promql.VectorSelector)
		sel.LabelMatchers = metric.LabelMatchers(append(sel.LabelMatchers, v.matcher))
	}

	return v
}
