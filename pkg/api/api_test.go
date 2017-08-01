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
)

func setupTest(t *testing.T, controller *gomock.Controller) (http.Handler, keystone.Driver, *storage.MockDriver) {
	//load test policy (where everything is allowed)
	viper.Set("maia.policy_file", "../test/policy.json")
	viper.Set("maia.label_value_ttl", "72h")

	//create test driver with the domains and projects from start-data.sql
	keystone := keystone.Mock()
	storage := storage.NewMockDriver(controller)
	//storage = storage.Prometheus("https://prometheus.staging.cloud.sap")
	router, _ := NewV1Router(keystone, storage)
	return router, keystone, storage
}

// HTTP based tests

func Test_Federate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, _, storageMock := setupTest(t, ctrl)

	storageMock.EXPECT().Federate([]string{"{vmware_name=\"win_cifs_13\",project_id=\"12345\"}"}, storage.PlainText).Return(test.HTTPResponseFromFile("fixtures/federate.txt"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id@12345:password")), "Accept": storage.PlainText},
		Method:           "GET",
		Path:             "/federate?match[]={vmware_name=%22win_cifs_13%22}",
		ExpectStatusCode: 200,
		ExpectFile:       "fixtures/federate.txt",
	}.Check(t, router)
}

func Test_Series(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, _, storageMock := setupTest(t, ctrl)

	storageMock.EXPECT().Series([]string{"{component!=\"\",project_id=\"12345\"}"}, "2017-07-01T20:10:30.781Z", "2017-07-02T04:00:00.000Z", "application/json").Return(test.HTTPResponseFromFile("fixtures/series.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id@12345:password")), "Accept": "application/json"},
		Method:           "GET",
		Path:             "/api/v1/series?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/series.json",
	}.Check(t, router)
}

func Test_LabelValues(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, _, storageMock := setupTest(t, ctrl)

	storageMock.EXPECT().Series([]string{"{project_id=\"12345\",component!=\"\"}"}, gomock.Any(), gomock.Any(), "application/json").Return(test.HTTPResponseFromFile("fixtures/series.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id@12345:password")), "Accept": "application/json"},
		Method:           "GET",
		Path:             "/api/v1/label/component/values",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/label_values.json",
	}.Check(t, router)
}

func TestQuery(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, _, storageMock := setupTest(t, ctrl)

	storageMock.EXPECT().Query("sum(blackbox_api_status_gauge{check=~\"keystone\",project_id=\"12345\"})", "2017-07-01T20:10:30.781Z", "24m", "application/json").Return(test.HTTPResponseFromFile("fixtures/query.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id@12345:password")), "Accept": "application/json"},
		Method:           "GET",
		Path:             "/api/v1/query?query=sum(blackbox_api_status_gauge{check%3D~%22keystone%22})&time=2017-07-01T20:10:30.781Z&timeout=24m",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/query.json",
	}.Check(t, router)
}

func TestQuery_syntaxError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, _, _ := setupTest(t, ctrl)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id@12345:password")), "Accept": "application/json"},
		Method:           "GET",
		Path:             "/api/v1/query?query=sum(blackbox_api_status_gauge{check%3D~%22keystone%22}&time=2017-07-01T20:10:30.781Z&timeout=24m",
		ExpectStatusCode: 400,
		ExpectJSON:       "fixtures/query_syntax_error.json",
	}.Check(t, router)
}

func TestQueryRange(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, _, storageMock := setupTest(t, ctrl)

	storageMock.EXPECT().QueryRange("sum(blackbox_api_status_gauge{check=~\"keystone\",project_id=\"12345\"})", "2017-07-01T20:10:30.781Z", "2017-07-02T04:00:00.000Z", "5m", "90s", "application/json").Return(test.HTTPResponseFromFile("fixtures/query_range.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id@12345:password")), "Accept": "application/json"},
		Method:           "GET",
		Path:             "/api/v1/query_range?query=sum(blackbox_api_status_gauge{check%3D~%22keystone%22})&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z&step=5m&timeout=90s",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/query_range.json",
	}.Check(t, router)
}

func TestAPIMetadata(t *testing.T) {
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
