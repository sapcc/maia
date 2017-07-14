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
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/test"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http/httptest"
)

func setupTest(t *testing.T, controller *gomock.Controller) (http.Handler, keystone.Driver, *storage.MockDriver) {
	//load test policy (where everything is allowed)
	viper.Set("maia.policy_file", "../test/policy.json")

	//create test driver with the domains and projects from start-data.sql
	keystone := keystone.Mock()
	storage := storage.NewMockDriver(controller)
	//storage = storage.Prometheus("https://prometheus.staging.cloud.sap")
	router, _ := NewV1Router(keystone, storage)
	return router, keystone, storage
}

// HTTP based tests
func Test_Query(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, _, storageMock := setupTest(t, ctrl)

	storageMock.EXPECT().Query("sum(blackbox_api_status_gauge{check=~\"keystone\",project_id=\"12345\"})", "", "", "application/json").Return(httpResponseFromFile("fixtures/query.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id@12345:password")), "Accept": "application/json"},
		Method:           "GET",
		Path:             "/api/v1/query?query=sum(blackbox_api_status_gauge{check%3D~%22keystone%22})",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/query.json",
	}.Check(t, router)

}
func httpResponseFromFile(filename string) *http.Response {
	fixture, _ := ioutil.ReadFile(filename)
	responseRec := httptest.NewRecorder()
	responseRec.Write(fixture)
	return responseRec.Result()
}

func Test_APIMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, _, _ := setupTest(t, ctrl)

	test.APIRequest{
		Method:           "GET",
		Path:             "/api/v1/",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/api-metadata.json",
	}.Check(t, router)
}
