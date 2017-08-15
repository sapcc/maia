package util

import (
	"testing"
)

const expectedSelector = "{check=~\"$api\",project_id=\"ecdc9fc4165d49b78987bbfbd5b4c9e2\"}"
const expectedExpr = "1 - sum(blackbox_api_status_gauge" + expectedSelector + ")"
const expectedSelectorMulti = "{check=~\"$api\",project_id=~\"ecdc9fc4165d49b78987bbfbd5b4c9e2|xyz\"}"

func TestAddLabelConstraintToExpression(t *testing.T) {
	testpql, err := AddLabelConstraintToExpression("1 - sum(blackbox_api_status_gauge{check=~\"$api\"})", "project_id", []string{"ecdc9fc4165d49b78987bbfbd5b4c9e2"})
	if err != nil {
		t.Error(err)
	} else if testpql != expectedExpr {
		t.Errorf("Unexpected result: %s; should have been %s", testpql, expectedExpr)
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

func TestAddLabelConstraintToSelector_multi(t *testing.T) {
	result, err := AddLabelConstraintToSelector("{check=~\"$api\"}", "project_id", []string{"ecdc9fc4165d49b78987bbfbd5b4c9e2", "xyz"})
	if err != nil {
		t.Error(err)
	} else if result != expectedSelectorMulti {
		t.Errorf("Unexpected result: %s; should have been %s", result, expectedSelectorMulti)
	}
}
