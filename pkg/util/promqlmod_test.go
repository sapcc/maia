// Copyright 2024 SAP SE
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"fmt"
	"testing"
)

const expectedSelector = "{check=~\"$api\",project_id=\"ecdc9fc4165d49b78987bbfbd5b4c9e2\"}"

func TestAddLabelConstraintToExpressionWithUnless(t *testing.T) {
	modifiedExpr, err := AddLabelConstraintToExpression("limes_swift_size_bytes_per_container{container_name=~\"my-test-container\", project_id=\"caa1337d2c38450f8266311fd0f05446\"} unless (limes_swift_size_bytes_per_container{container_name=~\"my-test-container-segments\", project_id=\"caa1337d2c38450f8266311fd0f05446\"} < 3)", "project_id", []string{"test123"})
	if err != nil {
		t.Fatalf("Error modifying expression: %v", err)
	}
	expected := "limes_swift_size_bytes_per_container{container_name=~\"my-test-container\",project_id=\"caa1337d2c38450f8266311fd0f05446\",project_id=\"test123\"} unless (limes_swift_size_bytes_per_container{container_name=~\"my-test-container-segments\",project_id=\"caa1337d2c38450f8266311fd0f05446\",project_id=\"test123\"} < 3)"
	if modifiedExpr != expected {
		t.Errorf("Expected modified expression to be %q, but got %q", expected, modifiedExpr)
	}
}

func TestAddLabelConstraintToExpressionWithSumRateAndUnless(t *testing.T) {
	modifiedExpr, err := AddLabelConstraintToExpression("sum by (container_name) (rate(limes_swift_size_bytes_per_container{container_name=~\"my-test-container\", project_id=\"caa1337d2c38450f8266311fd0f05446\"}[5m]) unless rate(limes_swift_size_bytes_per_container{container_name=~\"my-test-container-segments\", project_id=\"caa1337d2c38450f8266311fd0f05446\"}[5m]) < 3)",
		"project_id", []string{"test123"})
	if err != nil {
		t.Fatalf("Error modifying expression: %v", err)
	}
	expected := "sum by (container_name) (rate(limes_swift_size_bytes_per_container{container_name=~\"my-test-container\",project_id=\"caa1337d2c38450f8266311fd0f05446\",project_id=\"test123\"}[5m]) unless rate(limes_swift_size_bytes_per_container{container_name=~\"my-test-container-segments\",project_id=\"caa1337d2c38450f8266311fd0f05446\",project_id=\"test123\"}[5m]) < 3)"
	if modifiedExpr != expected {
		t.Errorf("Expected modified expression to be %q, but got %q", expected, modifiedExpr)
	}
}

func TestAddLabelConstraintToExpression(t *testing.T) {
	modifiedExpr, err := AddLabelConstraintToExpression("sum(rate(http_request_total{job=\"myjob\", code=\"200\"}[5m])) by (job)", "project_id", []string{"12345"})
	if err != nil {
		t.Fatalf("Error modifying expression: %v", err)
	}
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
	for i := range 100 {
		values[i] = fmt.Sprintf("value%d", i)
	}
	_, err := AddLabelConstraintToExpression("sum(rate(http_request_total{job=\"myjob\"}[5m])) by (job)", "project_id", values)
	if err != nil {
		t.Errorf("Error modifying expression with large values: %v", err)
	}
}
