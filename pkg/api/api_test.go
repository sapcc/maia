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

	"github.com/databus23/goslo.policy"
	"github.com/golang/mock/gomock"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/test"
	"github.com/spf13/viper"
)

func setupTest(t *testing.T, controller *gomock.Controller) (http.Handler, *keystone.MockDriver, *storage.MockDriver) {
	//load test policy (where everything is allowed)
	viper.Set("maia.policy_file", "../test/policy.json")
	viper.Set("maia.label_value_ttl", "72h")

	//create test driver with the domains and projects from start-data.sql
	keystone := keystone.NewMockDriver(controller)
	storage := storage.NewMockDriver(controller)
	//storage = storage.Prometheus("https://prometheus.staging.cloud.sap")
	router, _ := NewV1Router(keystone, storage)
	return router, keystone, storage
}

func expectAuthByProjectID(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: map[string]string{"X-Project-Id": "12345"}}
	authCall := keystoneMock.EXPECT().AuthenticateRequest(httpReqMatcher).Return(&policy.Context{Request: map[string]string{"user_id": "testuser",
		"project_id": "12345", "password": "testwd"}, Auth: map[string]string{"project_id": "12345"}, Roles: []string{"monitoring_viewer"}}, nil)
	keystoneMock.EXPECT().ChildProjects("12345").Return([]string{}).After(authCall)
}

func expectAuthByDomainName(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: map[string]string{"X-Domain-Id": "77777"}}
	keystoneMock.EXPECT().AuthenticateRequest(httpReqMatcher).Return(&policy.Context{Request: map[string]string{"user_id": "testuser",
		"domain_id": "77777", "password": "testwd"}, Auth: map[string]string{"domain_id": "77777"}, Roles: []string{"monitoring_viewer"}}, nil)
}

func expectAuthWithChildren(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: map[string]string{"X-Project-Id": "12345"}}
	authCall := keystoneMock.EXPECT().AuthenticateRequest(httpReqMatcher).Return(&policy.Context{Request: map[string]string{"user_id": "testuser",
		"project_id": "12345", "password": "testwd"}, Auth: map[string]string{"project_id": "12345"}, Roles: []string{"monitoring_viewer"}}, nil)
	keystoneMock.EXPECT().ChildProjects("12345").Return([]string{"67890"}).After(authCall)
}

// HTTP based tests

func Test_Federate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByDomainName(keystoneMock)
	storageMock.EXPECT().Federate([]string{"{vmware_name=\"win_cifs_13\",domain_id=\"77777\"}"}, storage.PlainText).Return(test.HTTPResponseFromFile("fixtures/federate.txt"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|@77777:password")), "Accept": storage.PlainText},
		Method:           "GET",
		Path:             "/federate?match[]={vmware_name=%22win_cifs_13%22}",
		ExpectStatusCode: 200,
		ExpectFile:       "fixtures/federate.txt",
	}.Check(t, router)
}

func Test_Series(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthWithChildren(keystoneMock)
	storageMock.EXPECT().Series([]string{"{component!=\"\",project_id=\"12345|67890\"}"}, "2017-07-01T20:10:30.781Z", "2017-07-02T04:00:00.000Z", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/series.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"X-Auth-Token": "someverylongtokenideed", "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/series?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/series.json",
	}.Check(t, router)
}
func Test_LabelValues(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByProjectID(keystoneMock)
	// Maia's label-values implementation uses the series API and a time-based filter stale series out. The exact start
	// and end date of the filter cannot be predicted, therefore we accept anything that is a parsable date.
	storageMock.EXPECT().Series([]string{"{project_id=\"12345\",component!=\"\"}"}, test.TimeStringMatcher{}, test.TimeStringMatcher{}, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/series.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/label/component/values",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/label_values.json",
	}.Check(t, router)
}

func TestQuery(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByProjectID(keystoneMock)
	storageMock.EXPECT().Query("sum(blackbox_api_status_gauge{check=~\"keystone\",project_id=\"12345\"})", "2017-07-01T20:10:30.781Z", "24m", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/query?query=sum(blackbox_api_status_gauge{check%3D~%22keystone%22})&time=2017-07-01T20:10:30.781Z&timeout=24m",
		ExpectStatusCode: 200,
		ExpectJSON:       "fixtures/query.json",
	}.Check(t, router)
}

func TestQuery_syntaxError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthByProjectID(keystoneMock)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/query?query=sum(blackbox_api_status_gauge{check%3D~%22keystone%22}&time=2017-07-01T20:10:30.781Z&timeout=24m",
		ExpectStatusCode: 400,
		ExpectJSON:       "fixtures/query_syntax_error.json",
	}.Check(t, router)
}

func TestQueryRange(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByProjectID(keystoneMock)
	storageMock.EXPECT().QueryRange("sum(blackbox_api_status_gauge{check=~\"keystone\",project_id=\"12345\"})", "2017-07-01T20:10:30.781Z", "2017-07-02T04:00:00.000Z", "5m", "90s", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query_range.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
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
