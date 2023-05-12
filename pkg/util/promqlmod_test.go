package util

import (
	"fmt"
	"testing"

	"github.com/prometheus/prometheus/promql/parser"
)

const expectedSelector = "{check=~\"$api\",project_id=\"ecdc9fc4165d49b78987bbfbd5b4c9e2\"}"

// const expectedExpr = "1 - sum(blackbox_api_status_gauge" + expectedSelector + ")"
// const expectedSelectorMulti = "{check=~\"$api\",project_id=~\"ecdc9fc4165d49b78987bbfbd5b4c9e2|xyz\"}"

func TestAddLabelConstraintToExpression(t *testing.T) {
	modifiedExpr, err := AddLabelConstraintToExpression("sum(rate(http_request_total{job=\"myjob\", code=\"200\"}[5m])) by (job)", "project_id", []string{"12345"})
	if err != nil {
		t.Fatalf("Error modifying expression: %v", err)
	}
	// This has changed to the new format from the old one
	expected := "sum by (job) (rate(http_request_total{code=\"200\",job=\"myjob\",project_id=\"12345\"}[5m]))"
	if modifiedExpr != expected {
		t.Errorf("Expected modified expression to be %q, but got %q", expected, modifiedExpr)
	}
}

func TestAddLabelConstraintToSelector(t *testing.T) {
	result, err := AddLabelConstraintToSelector("{check=~\"$api\"}", "project_id", []string{"ecdc9fc4165d49b78987bbfbd5b4c9e2"})
	if err != nil {
		t.Error(err)
	} else if result != expectedSelector {
		t.Errorf("Unexpected result: %s; should have been %s", result, expectedSelector)
	}
}

func TestAddLabelConstraintToExpression_InvalidExpression(t *testing.T) {
	_, err := AddLabelConstraintToExpression("invalid expression", "project_id", []string{"12345"})
	if err == nil {
		t.Errorf("Expected error due to invalid expression, but got none")
	}
}

func TestAddLabelConstraintToExpression_LargeValues(t *testing.T) {
	values := make([]string, 100)
	for i := 0; i < 100; i++ {
		values[i] = fmt.Sprintf("value%d", i)
	}
	_, err := AddLabelConstraintToExpression("sum(rate(http_request_total{job=\"myjob\"}[5m])) by (job)", "project_id", values)
	if err != nil {
		t.Errorf("Error modifying expression with large values: %v", err)
	}
}

// This is failing, project_id is not being added to the expression, LabelMatchers includes job and __name__ but not project_id
// are we not replacing the old node with the new node?
func TestVisit(t *testing.T) {
	// Create a label matcher
	matcher, err := makeLabelMatcher("project_id", []string{"12345"})
	if err != nil {
		t.Fatalf("Error creating label matcher: %v", err)
	}

	// Create a labelInjector
	v := labelInjector{matcher: matcher}

	// Parse a PromQL expression that includes a VectorSelector
	expr, err := parser.ParseExpr("http_request_total{job=\"myjob\"}")
	if err != nil {
		t.Fatalf("Error parsing expression: %v", err)
	}

	// Get the VectorSelector node from the parsed expression
	vectorSelectorNode := expr.(*parser.VectorSelector) //nolint:errcheck

	// Call Visit on the VectorSelector node
	_, err = v.Visit(vectorSelectorNode, nil)
	if err != nil {
		t.Fatalf("Error calling Visit: %v", err)
	}

	// Check that the label constraint was correctly injected
	expectedMatcherString := matcher.String()
	found := false
	for _, m := range vectorSelectorNode.LabelMatchers {
		if m.String() == expectedMatcherString {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Label constraint not found in VectorSelector node after calling Visit")
	}
}
