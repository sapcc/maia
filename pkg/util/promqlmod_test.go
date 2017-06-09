package util

import (
	"github.com/prometheus/prometheus/promql"
	"testing"
)

const expected = "1 - sum(blackbox_api_status_gauge{check=~\"$api\",project_id=\"ecdc9fc4165d49b78987bbfbd5b4c9e2\"})"

func TestLabelInjector_VisitInjector(t *testing.T) {
	testpql, err := promql.ParseExpr("1 - sum(blackbox_api_status_gauge{check=~\"$api\"})")
	if err != nil {
		t.Fatal(err)
	}
	AddLabelConstraint(testpql, "project_id", "ecdc9fc4165d49b78987bbfbd5b4c9e2")
	if testpql.String() != expected {
		t.Errorf("Unexpected result: %s; should have been %s", testpql.String(), expected)
	}
}
