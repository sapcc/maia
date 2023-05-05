package util

import (
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

// AddLabelConstraintToExpression enhances a PromQL expression to limit it to series matching a certain label
func AddLabelConstraintToExpression(expression, key string, values []string) (string, error) {
	// Parse the given PromQL expression
	exprNode, err := parser.ParseExpr(expression)
	if err != nil {
		return "", err
	}

	// Create a label matcher based on the provided key and values
	matcher, err := makeLabelMatcher(key, values)
	if err != nil {
		return "", err
	}

	// Initialize labelInjector with the created matcher and a nodeReplacer function
	v := labelInjector{
		matcher: matcher,
		nodeReplacer: func(oldNode, newNode parser.Node) {
			parent, found := findParentNode(exprNode, oldNode)
			if found {
				replaceChildNode(parent, oldNode, newNode)
			} else {
				exprNode = newNode.(parser.Expr) //nolint:errcheck
			}
		},
	}

	// Walk the PromQL expression tree and modify label matchers
	err = parser.Walk(v, exprNode, nil)
	if err != nil {
		return "", err
	}

	// Return the modified PromQL expression as a string
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
	matcher      *labels.Matcher
	nodeReplacer func(parser.Node, parser.Node)
}

// Visit modifies the label matchers of the visited parser.Node based on the labelInjector's matcher
func (v labelInjector) Visit(node parser.Node, path []parser.Node) (parser.Visitor, error) {
	switch n := node.(type) {
	case *parser.MatrixSelector:
		vs, ok := n.VectorSelector.(*parser.VectorSelector)
		if !ok {
			return v, nil
		}
		sel := &parser.MatrixSelector{
			VectorSelector: &parser.VectorSelector{
				LabelMatchers: append(vs.LabelMatchers, v.matcher),
			},
			Range: n.Range,
		}
		v.nodeReplacer(node, sel)
	case *parser.VectorSelector:
		sel := &parser.VectorSelector{
			LabelMatchers: append(n.LabelMatchers, v.matcher),
		}
		v.nodeReplacer(node, sel)
	}

	return v, nil
}

// replaceChildNode replaces the oldChild node with the newChild node in the parent node
func replaceChildNode(parent, oldChild, newChild parser.Node) {
	switch p := parent.(type) {
	case *parser.AggregateExpr:
		if p.Expr == oldChild {
			p.Expr = newChild.(parser.Expr) //nolint:errcheck
		}
	case *parser.BinaryExpr:
		if p.LHS == oldChild {
			p.LHS = newChild.(parser.Expr) //nolint:errcheck
		} else if p.RHS == oldChild {
			p.RHS = newChild.(parser.Expr) //nolint:errcheck
		}
	case *parser.Call:
		for i, e := range p.Args {
			if e == oldChild {
				p.Args[i] = newChild.(parser.Expr) //nolint:errcheck
				return
			}
		}
	case *parser.ParenExpr:
		if p.Expr == oldChild {
			p.Expr = newChild.(parser.Expr) //nolint:errcheck
		}
	case *parser.UnaryExpr:
		if p.Expr == oldChild {
			p.Expr = newChild.(parser.Expr) //nolint:errcheck
		}
	}
}

// findParentNode finds the parent node of the target node in the given root node
func findParentNode(root, target parser.Node) (parser.Node, bool) {
	var parentNode parser.Node
	var found bool
	v := &parentNodeFinder{
		target: target,
		found:  &found,
	}

	// Walk the PromQL expression tree and find the parent node of the target node
	err := parser.Walk(v, root, nil)
	if err != nil {
		return nil, false
	}
	parentNode = v.parent
	return parentNode, found
}

// parentNodeFinder is a parser.Visitor that finds the parent node of a given target node
type parentNodeFinder struct {
	target parser.Node
	parent parser.Node
	found  *bool
}

// Visit finds the parent node of the target node
func (v *parentNodeFinder) Visit(node parser.Node, path []parser.Node) (parser.Visitor, error) {
	if *v.found {
		return nil, nil
	}

	// Check if the current node has the target node as a child
	for _, child := range parser.Children(node) {
		if child == v.target {
			v.parent = node
			*v.found = true
			break
		}
	}
	return v, nil
}
