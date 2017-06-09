package util

import (
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage/metric"
)

func AddLabelConstraint(node promql.Node, key string, value string) {
	// matcher := model.Matcher{model.LabelName(key), value, false}
	matcher, _ := metric.NewLabelMatcher(metric.Equal, model.LabelName(key), model.LabelValue(value))
	promql.Walk(labelInjector{matcher: matcher}, node)
}

type labelInjector struct {
	promql.Visitor
	matcher *metric.LabelMatcher
}

func (v labelInjector) Visit(node promql.Node) (w promql.Visitor) {
	switch node.(type) {
	case *promql.VectorSelector:
		sel := node.(*promql.VectorSelector)
		sel.LabelMatchers = metric.LabelMatchers(append(sel.LabelMatchers, v.matcher))
	}

	return v
}
