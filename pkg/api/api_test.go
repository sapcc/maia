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

	"errors"

	policy "github.com/databus23/goslo.policy"
	"github.com/golang/mock/gomock"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"

	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/test"
)

var projectContext = &policy.Context{Request: map[string]string{"project_id": "12345", "domain_id": "77777", "user_id": "u12345"},
	Auth: map[string]string{"project_id": "12345", "project_name": "testproject",
		"project_domain_name": "testdomain", "project_domain_id": "77777",
		"user_id": "u12345", "user_name": "testuser", "user_domain_name": "testdomain", "user_domain_id": "77777"},
	Roles: []string{"monitoring_viewer"}}
var projectInsufficientRolesContext = &policy.Context{Request: map[string]string{"project_id": "12345", "domain_id": "77777", "user_id": "u12345"},
	Auth: map[string]string{"project_id": "12345", "project_name": "testproject",
		"project_domain_name": "testdomain", "project_domain_id": "77777",
		"user_id": "u12345", "user_name": "testuser", "user_domain_name": "testdomain", "user_domain_id": "77777"},
	Roles: []string{"member"}}
var projectHeader = map[string]string{"X-User-Id": projectContext.Auth["user_id"], "X-User-Name": projectContext.Auth["user_name"],
	"X-User-Domain-Name": projectContext.Auth["user_domain_name"],
	"X-Project-Id":       projectContext.Auth["project_id"], "X-Project-Name": projectContext.Auth["project_name"]}
var domainContext = &policy.Context{Request: map[string]string{"project_id": "12345", "domain_id": "77777", "user_id": "u12345"},
	Auth: map[string]string{"domain_id": "77777", "domain_name": "testdomain",
		"user_id": "u12345", "user_name": "testuser", "user_domain_name": "testdomain", "user_domain_id": "77777"},
	Roles: []string{"monitoring_viewer"}}
var domainHeader = map[string]string{"X-User-Id": domainContext.Auth["user_id"], "X-User-Name": domainContext.Auth["user_name"],
	"X-User-Domain-Name": domainContext.Auth["user_domain_name"],
	"X-Domain-Id":        domainContext.Auth["domain_id"], "X-Domain-Name": domainContext.Auth["domain_name"]}

func setupTest(t *testing.T, controller *gomock.Controller) (router http.Handler, keystoneDriver *keystone.MockDriver, storageDriver *storage.MockDriver) { //nolint:unparam
	//load test policy (where everything is allowed)
	viper.Set("keystone.policy_file", "../test/policy.json")
	viper.Set("maia.label_value_ttl", "72h")

	//create test driver with the domains and projects from start-data.sql
	keystoneDriver = keystone.NewMockDriver(controller)
	storageDriver = storage.NewMockDriver(controller)

	prometheus.DefaultRegisterer = prometheus.NewPedanticRegistry()
	router = setupRouter(keystoneDriver, storageDriver)

	return router, keystoneDriver, storageDriver
}

func expectAuthByProjectID(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	authCall := keystoneMock.EXPECT().AuthenticateRequest(httpReqMatcher, false).Return(projectContext, nil)
	keystoneMock.EXPECT().ChildProjects(projectContext.Auth["project_id"]).Return([]string{}, nil).After(authCall)
}

func expectAuthByDomainName(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: domainHeader}
	keystoneMock.EXPECT().AuthenticateRequest(httpReqMatcher, false).Return(domainContext, nil)
}

func expectAuthWithChildren(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	authCall := keystoneMock.EXPECT().AuthenticateRequest(httpReqMatcher, false).Return(projectContext, nil)
	keystoneMock.EXPECT().ChildProjects(projectContext.Auth["project_id"]).Return([]string{"67890"}, nil).After(authCall)
}

func expectAuthByDefaults(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	authCall := keystoneMock.EXPECT().AuthenticateRequest(httpReqMatcher, true).Return(projectContext, nil)
	keystoneMock.EXPECT().UserProjects(projectContext.Auth["user_id"]).Return([]tokens.Scope{{ProjectID: projectContext.Auth["project_id"], DomainID: projectContext.Auth["project_domain_id"]}}, nil).After(authCall)
}

func expectAuthAndFail(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	keystoneMock.EXPECT().AuthenticateRequest(httpReqMatcher, false).Return(nil, keystone.NewAuthenticationError(keystone.StatusWrongCredentials, "negativetesterror"))
}

func expectPlainBasicAuthAndFail(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	keystoneMock.EXPECT().AuthenticateRequest(httpReqMatcher, true).Return(nil, keystone.NewAuthenticationError(keystone.StatusWrongCredentials, "negativetesterror"))
}

func expectAuthAndDenyAuthorization(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	keystoneMock.EXPECT().AuthenticateRequest(httpReqMatcher, false).Return(projectInsufficientRolesContext, nil)
}

// HTTP based tests

func TestFederate(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByDomainName(keystoneMock)
	storageMock.EXPECT().Federate([]string{"{vmware_name=\"win_cifs_13\",domain_id=\"77777\"}"}, storage.PlainText).Return(test.HTTPResponseFromFile("fixtures/federate.txt"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic u12345|@77777:password")), "Accept": storage.PlainText},
		Method:           "GET",
		Path:             "/federate?match[]={vmware_name=%22win_cifs_13%22}",
		ExpectStatusCode: http.StatusOK,
		ExpectFile:       "fixtures/federate.txt",
	}.Check(t, router)
}

func TestFederate_errorNoMatch(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthByDomainName(keystoneMock)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic u12345|@77777:password")), "Accept": storage.PlainText},
		Method:           "GET",
		Path:             "/federate?bla[]={vmwa...}",
		ExpectStatusCode: http.StatusBadRequest,
	}.Check(t, router)
}

func TestFederate_errorInvalidSelector(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthByDomainName(keystoneMock)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic u12345|@77777:password")), "Accept": storage.PlainText},
		Method:           "GET",
		Path:             "/federate?match[]={invalid_syntax=}",
		ExpectStatusCode: http.StatusBadRequest,
	}.Check(t, router)
}

func TestFederate_errorBackendFailed(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByDomainName(keystoneMock)
	storageMock.EXPECT().Federate([]string{"{vmware_name=\"win_cifs_13\",domain_id=\"77777\"}"}, storage.PlainText).Return(nil, errors.New("testerror"))

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic u12345|@77777:password")), "Accept": storage.PlainText},
		Method:           "GET",
		Path:             "/federate?match[]={vmware_name=%22win_cifs_13%22}",
		ExpectStatusCode: http.StatusServiceUnavailable,
	}.Check(t, router)
}

func TestSeries(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthWithChildren(keystoneMock)
	storageMock.EXPECT().Series([]string{"{component!=\"\",project_id=~\"12345|67890\"}"}, "2017-07-01T20:10:30.781Z", "2017-07-02T04:00:00.000Z", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/series.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"X-Auth-Token": "someverylongtokenideed", "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/series?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
		ExpectStatusCode: http.StatusOK,
		ExpectJSON:       "fixtures/series.json",
	}.Check(t, router)
}

func TestSeries_failAuthentication(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthAndFail(keystoneMock)

	test.APIRequest{
		Method:           "GET",
		Path:             "/api/v1/series?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
		ExpectStatusCode: http.StatusUnauthorized,
	}.Check(t, router)
}

func TestSeries_failAuthorization(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthAndDenyAuthorization(keystoneMock)

	test.APIRequest{
		Method:           "GET",
		Path:             "/api/v1/series?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
		ExpectStatusCode: http.StatusForbidden,
	}.Check(t, router)
}

func TestLabelValues(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByProjectID(keystoneMock)
	// Maia's label-values implementation uses the series API and a time-based filter stale series out. The exact start
	// and end date of the filter cannot be predicted, therefore we accept anything that is a parsable date.
	storageMock.EXPECT().QueryRange("count by (service) ({project_id=\"12345\",service!=\"\"})", test.TimeStringMatcher{}, test.TimeStringMatcher{}, viper.Get("maia.label_value_ttl"), "", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/label_values_query_range.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/label/service/values",
		ExpectStatusCode: http.StatusOK,
		ExpectJSON:       "fixtures/label_values.json",
	}.Check(t, router)
}

func TestQuery(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByProjectID(keystoneMock)
	storageMock.EXPECT().Query("sum(blackbox_api_status_gauge{check=~\"keystone\",project_id=\"12345\"})", "2017-07-01T20:10:30.781Z", "24m", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/query?query=sum(blackbox_api_status_gauge{check%3D~%22keystone%22})&time=2017-07-01T20:10:30.781Z&timeout=24m",
		ExpectStatusCode: http.StatusOK,
		ExpectJSON:       "fixtures/query.json",
	}.Check(t, router)
}

func TestQuery_syntaxError(t *testing.T) {
	ctrl := gomock.NewController(t)

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

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByProjectID(keystoneMock)
	storageMock.EXPECT().QueryRange("sum({__name__=\"blackbox_api_status_gauge\",check=~\"keystone\",project_id=\"12345\"})", "2017-07-01T20:10:30.781Z", "2017-07-02T04:00:00.000Z", "5m", "90s", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query_range.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/query_range?query=sum(%7B__name__%3D%22blackbox_api_status_gauge%22%2Ccheck%3D~%22keystone%22%2Cproject_id%3D%2212345%22%7D)&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z&step=5m&timeout=90s",
		ExpectStatusCode: http.StatusOK,
		ExpectJSON:       "fixtures/query_range.json",
	}.Check(t, router)
}

func TestAPIMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	keystoneMock.EXPECT().ServiceURL().Return("http://localhost:9091/api/v1")

	test.APIRequest{
		Method:           "GET",
		Path:             "/api",
		ExpectStatusCode: 300,
		ExpectJSON:       "fixtures/api-metadata.json",
	}.Check(t, router)
}

func TestServeStaticContent(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, _, _ := setupTest(t, ctrl)

	test.APIRequest{
		Method:           "GET",
		Path:             "/static/css/graph.css",
		ExpectStatusCode: http.StatusOK,
		ExpectFile:       "../../web/static/css/graph.css",
	}.Check(t, router)
}

func TestServeStaticContent_notFound(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, _, _ := setupTest(t, ctrl)

	test.APIRequest{
		Method:           "GET",
		Path:             "/static/bla.xyz",
		ExpectStatusCode: http.StatusNotFound,
	}.Check(t, router)
}

func TestGraph(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)
	expectAuthByDefaults(keystoneMock)

	test.APIRequest{
		Method:           "GET",
		Path:             "/testdomain/graph?project_id=" + projectContext.Auth["project_id"],
		ExpectStatusCode: http.StatusOK,
	}.Check(t, router)
}

func TestRoot_redirect(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, _, _ := setupTest(t, ctrl)

	test.APIRequest{
		Method:           "GET",
		Path:             "/" + projectContext.Auth["project_id"],
		ExpectStatusCode: http.StatusFound,
	}.Check(t, router)
}

func TestGraph_redirect(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, _, _ := setupTest(t, ctrl)

	test.APIRequest{
		Method:           "GET",
		Path:             "/graph?project_id=" + projectContext.Auth["project_id"],
		ExpectStatusCode: http.StatusFound,
	}.Check(t, router)
}

func TestGraph_otherOSDomain(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)
	expectPlainBasicAuthAndFail(keystoneMock)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic testuser|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/nottestdomain/graph?project_id=" + projectContext.Auth["project_id"],
		ExpectStatusCode: http.StatusUnauthorized,
	}.Check(t, router)
}
