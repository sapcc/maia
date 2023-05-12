package util

import (
	"fmt"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
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
	// It also includes a nodeReplacer function that will replace nodes in the syntax tree with modified versions.
	v := labelInjector{
		matcher: matcher,
		nodeReplacer: func(oldNode, newNode parser.Node) {
			// Find the parent of the old node in the syntax tree.
			parent, found := findParentNode(exprNode, oldNode)
			if found {
				// If the old node has a parent (it's not the root of the syntax tree), replace the old node with the new node.
				replaceChildNode(parent, oldNode, newNode)
			} else {
				// If the old node doesn't have a parent (it's the root of the syntax tree), replace the root with the new node.
				exprNode = newNode.(parser.Expr) //nolint:errcheck
			}
		},
	}

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
	fmt.Printf("Root Node: %v, Target Node: %v\n", root, target)
	v := &parentNodeFinder{
		targetNode: target,
	}
	err := parser.Walk(v, root, []parser.Node{})
	if err != nil {
		return nil, false
	}
	return v.parentNode, v.parentNode != nil
}

// parentNodeFinder is a parser.Visitor that finds the parent node of a given target node
type parentNodeFinder struct {
	targetNode parser.Node
	parentNode parser.Node
	stack      []parser.Node
}

// Visit finds the parent node of the target node
func (v *parentNodeFinder) Visit(node parser.Node, next []parser.Node) (w parser.Visitor, err error) {
	fmt.Println("Entering Visit function")

	// Check if the node is nil, and if it is, return v to continue the traversal
	if node == nil {
		fmt.Println("Node is nil")
		return v, nil
	}

	fmt.Printf("Current Node: %v\n", node)
	fmt.Printf("Current Stack: %v\n", v.stack)

	if node == v.targetNode {
		// Check if v.stack is not empty before accessing its last element
		if len(v.stack) > 0 {
			v.parentNode = v.stack[len(v.stack)-1]
			fmt.Printf("Parent Node found: %v\n", v.parentNode)
		} else {
			fmt.Println("Stack is empty, no parent node found")
		}
	} else {
		v.stack = append(v.stack, node)
		defer func() {
			// Similarly, check if v.stack is not empty before reducing its size
			if len(v.stack) > 0 {
				v.stack = v.stack[:len(v.stack)-1]
			}
		}()
	}

	fmt.Println("Exiting Visit function")
	return v, nil
}
