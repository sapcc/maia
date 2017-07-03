/*******************************************************************************
*
* Copyright 2017 SAP SE
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You should have received a copy of the License along with this
* program. If not, you may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*******************************************************************************/

package api

import (
	"net/http"
	"testing"

	"encoding/json"
	"github.com/databus23/goslo.policy"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/test"
	"github.com/spf13/viper"
	"io/ioutil"
)

func setupTest(t *testing.T) http.Handler {
	//load test policy (where everything is allowed)
	policyBytes, err := ioutil.ReadFile("../test/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	policyRules := make(map[string]string)
	err = json.Unmarshal(policyBytes, &policyRules)
	if err != nil {
		t.Fatal(err)
	}
	policyEnforcer, err := policy.NewEnforcer(policyRules)
	if err != nil {
		t.Fatal(err)
	}
	viper.Set("maia.policy_enforcer", policyEnforcer)

	//create test driver with the domains and projects from start-data.sql
	keystone := keystone.Mock()
	storage := storage.Mock()
	//storage = storage.Prometheus("https://prometheus.staging.cloud.sap")
	router, _ := NewV1Router(keystone, storage)
	return router
}

func Test_Query(t *testing.T) {
	router := setupTest(t)

	fixture, _ := ioutil.ReadFile("fixtures/query.json")
	storage.QueryResponseVal = string(fixture)
	test.APIRequest{
		Method:           "GET",
		Path:             "/api/v1/query?query=sum(blackbox_api_status_gauge{check%3D~%22keystone%22})",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/query.json",
	}.Check(t, router)

}

func Test_APIMetadata(t *testing.T) {
	router := setupTest(t)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user@project:password"))},
		Method:           "GET",
		Path:             "/api/v1/",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/api-metadata.json",
	}.Check(t, router)
}

func Test_Query(t *testing.T) {
	router := setupTest(t)

	test.APIRequest{
		Method:           "GET",
		Path:             "/api/v1/query?query=sum(blackbox_api_status_gauge{check=~%22keystone%22})",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/query.json",
	}.Check(t, router)

}
