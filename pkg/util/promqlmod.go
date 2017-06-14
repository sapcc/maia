package util

import (
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage/metric"
)

func AddLabelConstraintToExpression(expression string, key string, value string) (string, error) {
	exprNode, err := promql.ParseExpr(expression)
	if err != nil {
		return "", err
	}
	matcher, err := metric.NewLabelMatcher(metric.Equal, model.LabelName(key), model.LabelValue(value))
	if err != nil {
		return "", err
	}

	// since to structure of the expression is not modified we can use a visitor, avoiding our own traversal code
	promql.Walk(labelInjector{matcher: matcher}, exprNode)

	return exprNode.String(), nil
}

func AddLabelConstraintToSelector(metricSelector string, key string, value string) (string, error) {
	matcher, err := metric.NewLabelMatcher(metric.Equal, model.LabelName(key), model.LabelValue(value))
	if err != nil {
		return "", err
	}

	labelMatchers, err := promql.ParseMetricSelector(metricSelector)
	if err != nil {
		return "", err
	}
	return "{" + metric.LabelMatchers(append(labelMatchers, matcher)).String() + "}", nil
}

// restricts every reference to a metric (vector-selector) with an additional label-constraint
// we use this to restrict a query to metrics belonging to a single OpenStack tenants stored in label 'project_id'
type labelInjector struct {
	promql.Visitor
	matcher *metric.LabelMatcher
}

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
