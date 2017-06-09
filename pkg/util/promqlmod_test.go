package util

import (
	"github.com/prometheus/prometheus/promql"
	"testing"
)

const expectedSelector = "{check=~\"$api\",project_id=\"ecdc9fc4165d49b78987bbfbd5b4c9e2\"}"
const expectedExpr = "1 - sum(blackbox_api_status_gauge" + expectedSelector + ")"

func TestAddLabelConstraintToExpression(t *testing.T) {
	testpql, err := promql.ParseExpr("1 - sum(blackbox_api_status_gauge{check=~\"$api\"})")
	if err != nil {
		t.Fatal(err)
	}
	AddLabelConstraintToExpression(testpql, "project_id", "ecdc9fc4165d49b78987bbfbd5b4c9e2")
	if testpql.String() != expectedExpr {
		t.Errorf("Unexpected result: %s; should have been %s", testpql.String(), expectedExpr)
	}
}

func TestAddLabelConstraintToSelector(t *testing.T) {
	result := AddLabelConstraintToSelector("{check=~\"$api\"}", "project_id", "ecdc9fc4165d49b78987bbfbd5b4c9e2")
	if result != expectedSelector {
		t.Errorf("Unexpected result: %s; should have been %s", result, expectedSelector)
	}
}
