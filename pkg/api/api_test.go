// SPDX-FileCopyrightText: 2017 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"errors"

	policy "github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/SAP-cloud-infrastructure/maia/pkg/keystone"
	"github.com/SAP-cloud-infrastructure/maia/pkg/storage"
	"github.com/SAP-cloud-infrastructure/maia/pkg/test"
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
	// load test policy (where everything is allowed)
	viper.Set("keystone.policy_file", "../test/policy.json")
	viper.Set("maia.label_value_ttl", "72h")
	sentinelValue = "" // reset sentinel for each test

	// create test driver with the domains and projects from start-data.sql
	keystoneDriver = keystone.NewMockDriver(controller)
	storageDriver = storage.NewMockDriver(controller)

	prometheus.DefaultRegisterer = prometheus.NewPedanticRegistry()

	// Pass nil as globalKeystoneDriver for tests that don't need it
	router = setupRouter(keystoneDriver, nil, storageDriver)

	return router, keystoneDriver, storageDriver
}

func expectAuthByProjectID(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	authCall := keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), httpReqMatcher, false).Return(projectContext, nil)
	keystoneMock.EXPECT().ChildProjects(test.MatchContext(), projectContext.Auth["project_id"]).Return([]string{}, nil).After(authCall)
}

func expectAuthByDomainName(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: domainHeader}
	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), httpReqMatcher, false).Return(domainContext, nil)
}

func expectAuthWithChildren(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	authCall := keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), httpReqMatcher, false).Return(projectContext, nil)
	keystoneMock.EXPECT().ChildProjects(test.MatchContext(), projectContext.Auth["project_id"]).Return([]string{"67890"}, nil).After(authCall)
}

func expectAuthAndFail(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), httpReqMatcher, false).Return(nil, keystone.NewAuthenticationError(keystone.StatusWrongCredentials, "negativetesterror"))
}

func expectPlainBasicAuthAndFail(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), httpReqMatcher, true).Return(nil, keystone.NewAuthenticationError(keystone.StatusWrongCredentials, "negativetesterror"))
}

func expectAuthAndDenyAuthorization(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), httpReqMatcher, false).Return(projectInsufficientRolesContext, nil)
}

func expectAuthOnly(keystoneMock *keystone.MockDriver) {
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: map[string]string{
		"X-User-Id":          projectContext.Auth["user_id"],
		"X-User-Name":        projectContext.Auth["user_name"],
		"X-User-Domain-Name": projectContext.Auth["user_domain_name"],
		"X-Project-Id":       projectContext.Auth["project_id"],
		"X-Project-Name":     projectContext.Auth["project_name"],
		"X-Roles":            "monitoring_viewer",
	}}
	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), httpReqMatcher, false).Return(projectContext, nil)
}

func TestWhoami(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthOnly(keystoneMock)

	test.APIRequest{
		Headers:          map[string]string{"X-Auth-Token": "someverylongtokenideed"},
		Method:           "GET",
		Path:             "/api/v1/whoami",
		ExpectStatusCode: http.StatusOK,
		ExpectJSON:       "fixtures/whoami.json",
	}.Check(t, router)
}

func TestWhoami_unauthenticated(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), gomock.Any(), false).
		Return(nil, keystone.NewAuthenticationError(keystone.StatusMissingCredentials, "no credentials"))

	test.APIRequest{
		Method:           "GET",
		Path:             "/api/v1/whoami",
		ExpectStatusCode: http.StatusUnauthorized,
	}.Check(t, router)
}

func TestProjects(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthOnly(keystoneMock)
	keystoneMock.EXPECT().UserProjects(test.MatchContext(), projectContext.Auth["user_id"]).
		Return([]tokens.Scope{
			{ProjectID: "12345", ProjectName: "testproject"},
			{ProjectID: "67890", ProjectName: "otherproject"},
		}, nil)

	test.APIRequest{
		Headers:          map[string]string{"X-Auth-Token": "someverylongtokenideed"},
		Method:           "GET",
		Path:             "/api/v1/projects",
		ExpectStatusCode: http.StatusOK,
		ExpectJSON:       "fixtures/projects.json",
	}.Check(t, router)
}

func TestProjects_unauthenticated(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), gomock.Any(), false).
		Return(nil, keystone.NewAuthenticationError(keystone.StatusMissingCredentials, "no credentials"))

	test.APIRequest{
		Method:           "GET",
		Path:             "/api/v1/projects",
		ExpectStatusCode: http.StatusUnauthorized,
	}.Check(t, router)
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

func TestFederate_withSentinel(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)
	sentinelValue = "all"

	expectAuthByDomainName(keystoneMock)
	storageMock.EXPECT().Federate([]string{`{vmware_name="win_cifs_13",domain_id=~"77777|all"}`}, storage.PlainText).Return(test.HTTPResponseFromFile("fixtures/federate.txt"), nil)

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

func TestSeries_withSentinel(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)
	sentinelValue = "all"

	expectAuthWithChildren(keystoneMock)
	storageMock.EXPECT().Series([]string{`{component!="",project_id=~"12345|67890|all"}`}, "2017-07-01T20:10:30.781Z", "2017-07-02T04:00:00.000Z", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/series.json"), nil)

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

func TestLabels(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthWithChildren(keystoneMock)
	storageMock.EXPECT().Labels(
		"2017-07-01T20:10:30.781Z",
		"2017-07-02T04:00:00.000Z",
		[]string{"{component!=\"\",project_id=~\"12345|67890\"}"},
		storage.JSON,
	).Return(test.HTTPResponseFromFile("fixtures/labels.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"X-Auth-Token": "someverylongtokenideed", "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/labels?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
		ExpectStatusCode: http.StatusOK,
		ExpectJSON:       "fixtures/labels.json",
	}.Check(t, router)
}

func TestLabels_withSentinel(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)
	sentinelValue = "all"

	expectAuthWithChildren(keystoneMock)
	storageMock.EXPECT().Labels(
		"2017-07-01T20:10:30.781Z",
		"2017-07-02T04:00:00.000Z",
		[]string{`{component!="",project_id=~"12345|67890|all"}`},
		storage.JSON,
	).Return(test.HTTPResponseFromFile("fixtures/labels.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"X-Auth-Token": "someverylongtokenideed", "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/labels?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
		ExpectStatusCode: http.StatusOK,
		ExpectJSON:       "fixtures/labels.json",
	}.Check(t, router)
}

func TestLabels_domainScope(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByDomainName(keystoneMock)
	storageMock.EXPECT().Labels(
		"2017-07-01T20:10:30.781Z",
		"2017-07-02T04:00:00.000Z",
		[]string{"{component!=\"\",domain_id=\"77777\"}"},
		storage.JSON,
	).Return(test.HTTPResponseFromFile("fixtures/labels.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic u12345|@77777:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/labels?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
		ExpectStatusCode: http.StatusOK,
		ExpectJSON:       "fixtures/labels.json",
	}.Check(t, router)
}

func TestLabels_errorNoMatch(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthByProjectID(keystoneMock)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/labels",
		ExpectStatusCode: http.StatusBadRequest,
	}.Check(t, router)
}

func TestLabels_errorInvalidSelector(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthByProjectID(keystoneMock)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/labels?match[]={invalid_syntax=}",
		ExpectStatusCode: http.StatusBadRequest,
	}.Check(t, router)
}

func TestLabels_errorBackendFailed(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthWithChildren(keystoneMock)
	storageMock.EXPECT().Labels(
		"2017-07-01T20:10:30.781Z",
		"2017-07-02T04:00:00.000Z",
		[]string{"{component!=\"\",project_id=~\"12345|67890\"}"},
		storage.JSON,
	).Return(nil, errors.New("testerror"))

	test.APIRequest{
		Headers:          map[string]string{"X-Auth-Token": "someverylongtokenideed", "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/labels?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
		ExpectStatusCode: http.StatusServiceUnavailable,
	}.Check(t, router)
}

func TestLabels_failAuthentication(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthAndFail(keystoneMock)

	test.APIRequest{
		Method:           "GET",
		Path:             "/api/v1/labels?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
		ExpectStatusCode: http.StatusUnauthorized,
	}.Check(t, router)
}

func TestLabels_failAuthorization(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	expectAuthAndDenyAuthorization(keystoneMock)

	test.APIRequest{
		Method:           "GET",
		Path:             "/api/v1/labels?match[]={component!=%22%22}&end=2017-07-02T04:00:00.000Z&start=2017-07-01T20:10:30.781Z",
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

func TestLabelValues_sentinelNames(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)
	sentinelValue = "all"

	expectAuthByProjectID(keystoneMock)
	storageMock.EXPECT().QueryRange(`count by (__name__) ({__name__!="",project_id=~"12345|all"})`, test.TimeStringMatcher{}, test.TimeStringMatcher{}, viper.Get("maia.label_value_ttl"), "", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/label_values_sentinel_names_query_range.json"), nil)

	expectedBody := `{"status":"success","data":["kube_node_info","tenant_metric"]}`
	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/label/__name__/values",
		ExpectStatusCode: http.StatusOK,
		ExpectBody:       &expectedBody,
	}.Check(t, router)
}

func TestLabelValues_sentinelLabel(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)
	sentinelValue = "all"

	expectAuthByProjectID(keystoneMock)
	storageMock.EXPECT().QueryRange(`count by (node) ({node!="",project_id=~"12345|all"})`, test.TimeStringMatcher{}, test.TimeStringMatcher{}, viper.Get("maia.label_value_ttl"), "", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/label_values_sentinel_node_query_range.json"), nil)

	expectedBody := `{"status":"success","data":["worker-1","worker-2"]}`
	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/label/node/values",
		ExpectStatusCode: http.StatusOK,
		ExpectBody:       &expectedBody,
	}.Check(t, router)
}

// TestLabelValues_errorNonMatrixResult verifies that LabelValues returns a 502
// error (not a panic) when the backing Prometheus query_range returns a
// non-matrix result type (e.g. a vector). Before the fix, the bare type
// assertion sr.Data.Value.(model.Matrix) in LabelValues would panic for any
// non-matrix Value.
func TestLabelValues_errorNonMatrixResult(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)

	expectAuthByProjectID(keystoneMock)
	storageMock.EXPECT().QueryRange(
		"count by (service) ({project_id=\"12345\",service!=\"\"})",
		test.TimeStringMatcher{}, test.TimeStringMatcher{},
		viper.Get("maia.label_value_ttl"), "", storage.JSON,
	).Return(test.HTTPResponseFromFile("fixtures/label_values_query_range_vector.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/label/service/values",
		ExpectStatusCode: http.StatusBadGateway,
		ExpectJSON:       "fixtures/label_values_nonmatrix_error.json",
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

func TestQuery_withSentinel(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)
	sentinelValue = "all"

	expectAuthByProjectID(keystoneMock)
	storageMock.EXPECT().Query(`sum(blackbox_api_status_gauge{check=~"keystone",project_id=~"12345|all"})`, "2017-07-01T20:10:30.781Z", "24m", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query.json"), nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password")), "Accept": storage.JSON},
		Method:           "GET",
		Path:             "/api/v1/query?query=sum(blackbox_api_status_gauge{check%3D~%22keystone%22})&time=2017-07-01T20:10:30.781Z&timeout=24m",
		ExpectStatusCode: http.StatusOK,
		ExpectJSON:       "fixtures/query.json",
	}.Check(t, router)
}

func TestQuery_sentinelDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)
	// Explicitly set sentinel to empty string to disable it
	sentinelValue = ""

	expectAuthByProjectID(keystoneMock)
	// With sentinel disabled, single project should use exact match (=) not regex (=~)
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

func TestQueryRange_withSentinel(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, storageMock := setupTest(t, ctrl)
	sentinelValue = "all"

	expectAuthByProjectID(keystoneMock)
	// When the user's query already contains project_id="12345", the injected
	// project_id=~"12345|all" is still added (different matcher type). Prometheus
	// ANDs them, so the regex is a harmless superset of the exact match.
	storageMock.EXPECT().QueryRange(`sum({__name__="blackbox_api_status_gauge",check=~"keystone",project_id="12345",project_id=~"12345|all"})`, "2017-07-01T20:10:30.781Z", "2017-07-02T04:00:00.000Z", "5m", "90s", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query_range.json"), nil)

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

	// Static content is no longer served — web/static/ was removed in Phase 4.
	test.APIRequest{
		Method:           "GET",
		Path:             "/static/css/graph.css",
		ExpectStatusCode: http.StatusNotFound,
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
	// /{domain}/graph is now a login stub: authenticate then redirect to /ui/query (302).
	// authorize() runs with guessScope=true; the token is project-scoped so UserProjects
	// is not called. loginAndRedirect does not invoke scopeToLabelConstraint so
	// ChildProjects is also not called — only AuthenticateRequest fires.
	httpReqMatcher := test.HTTPRequestMatcher{InjectHeader: projectHeader}
	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), httpReqMatcher, true).Return(projectContext, nil)

	test.APIRequest{
		Headers:          map[string]string{"Authorization": base64.StdEncoding.EncodeToString([]byte("Basic user_id|12345:password"))},
		Method:           "GET",
		Path:             "/testdomain/graph",
		ExpectStatusCode: http.StatusFound,
	}.Check(t, router)
}

func TestRoot_redirect(t *testing.T) {
	ctrl := gomock.NewController(t)

	router, keystoneMock, _ := setupTest(t, ctrl)

	// /{domain} now requires auth (login entry point) — no credentials → 401
	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), gomock.Any(), true).
		Return(nil, keystone.NewAuthenticationError(keystone.StatusMissingCredentials, "no credentials"))

	test.APIRequest{
		Method:           "GET",
		Path:             "/" + projectContext.Auth["project_id"],
		ExpectStatusCode: http.StatusUnauthorized,
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

func TestGlobalKeystoneRouting(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Set policy file path - this is crucial
	viper.Set("keystone.policy_file", "../test/policy.json")
	viper.Set("maia.label_value_ttl", "72h")

	// Create mock keystones
	regularKeystone := keystone.NewMockDriver(ctrl)
	globalKeystone := keystone.NewMockDriver(ctrl)

	// Store instances for restoration
	originalKeystone := keystoneInstance
	originalGlobalKeystone := globalKeystoneInstance

	// Set global instances for testing
	keystoneInstance = regularKeystone
	globalKeystoneInstance = globalKeystone

	// Restore instances after test
	defer func() {
		keystoneInstance = originalKeystone
		globalKeystoneInstance = originalGlobalKeystone
	}()

	// Setup storage mock
	storageMock := storage.NewMockDriver(ctrl)

	// Reset prometheus registry to avoid conflicts
	prometheus.DefaultRegisterer = prometheus.NewPedanticRegistry()

	// Setup router with both keystones
	router := setupRouter(regularKeystone, globalKeystone, storageMock)

	// Test cases
	testCases := []struct {
		name           string
		path           string
		globalParam    string
		globalHeader   string
		expectedDriver *keystone.MockDriver
	}{
		{"Regular request", "/api/v1/query", "", "", regularKeystone},
		{"Global param request", "/api/v1/query", "true", "", globalKeystone},
		{"Global header request", "/api/v1/query", "", "true", globalKeystone},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request with appropriate global params/headers
			url := tc.path
			if tc.globalParam != "" {
				url += "?global=" + tc.globalParam
			}
			req := httptest.NewRequest(http.MethodGet, url, http.NoBody)
			if tc.globalHeader != "" {
				req.Header.Set("X-Global-Region", tc.globalHeader)
			}

			// Set appropriate expectations on the expected driver
			tc.expectedDriver.EXPECT().AuthenticateRequest(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&policy.Context{}, nil)

			// Execute request
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
		})
	}
}

func TestRedirectPreservesGlobalFlag(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Store instances for restoration
	originalKeystone := keystoneInstance
	originalGlobalKeystone := globalKeystoneInstance

	// Create mock keystones
	regularKeystone := keystone.NewMockDriver(ctrl)
	globalKeystone := keystone.NewMockDriver(ctrl)

	// Set keystones
	keystoneInstance = regularKeystone
	globalKeystoneInstance = globalKeystone

	// Restore instances after test
	defer func() {
		keystoneInstance = originalKeystone
		globalKeystoneInstance = originalGlobalKeystone
	}()

	// Set policy file path - this is crucial
	viper.Set("keystone.policy_file", "../test/policy.json")
	viper.Set("maia.label_value_ttl", "72h")

	// Setup storage mock
	storageMock := storage.NewMockDriver(ctrl)

	// Reset prometheus registry to avoid conflicts
	prometheus.DefaultRegisterer = prometheus.NewPedanticRegistry()

	// Setup router with both keystones
	router := setupRouter(regularKeystone, globalKeystone, storageMock)

	// /graph (no domain) and / now redirect unconditionally to /ui/query.
	// The global flag is handled by the React UI via query params to /api/v1/*.
	t.Run("Redirect goes to /ui/query", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/graph?global=true", http.NoBody)

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		resp := recorder.Result()
		assert.Equal(t, http.StatusFound, resp.StatusCode, "Expected redirect")

		location := resp.Header.Get("Location")
		assert.Equal(t, "/ui/query", location, "Should redirect to /ui/query")
	})

	t.Run("Redirect with global header goes to /ui/query", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/graph", http.NoBody)
		req.Header.Set("X-Global-Region", "true")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		resp := recorder.Result()
		assert.Equal(t, http.StatusFound, resp.StatusCode, "Expected redirect")

		location := resp.Header.Get("Location")
		assert.Equal(t, "/ui/query", location, "Should redirect to /ui/query")
	})
}

func TestPostDomainLogin_bodyToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	router, keystoneMock, _ := setupTest(t, ctrl)

	// Expect the body token to be promoted to X-Auth-Token header before auth.
	matcher := test.HTTPRequestMatcher{
		ExpectHeader: map[string]string{"X-Auth-Token": "someverylongtokenindeed"},
		InjectHeader: projectHeader,
	}
	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), matcher, true).Return(projectContext, nil)

	body := strings.NewReader("x-auth-token=someverylongtokenindeed")
	req := httptest.NewRequest(http.MethodPost, "/testdomain", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/testdomain", resp.Header.Get("Location"))
}

func TestPostDomainLogin_headerTakesPrecedenceOverBody(t *testing.T) {
	ctrl := gomock.NewController(t)
	router, keystoneMock, _ := setupTest(t, ctrl)

	// Header token must win; body token must be ignored.
	matcher := test.HTTPRequestMatcher{
		ExpectHeader: map[string]string{"X-Auth-Token": "headertoken"},
		InjectHeader: projectHeader,
	}
	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), matcher, true).Return(projectContext, nil)

	body := strings.NewReader("x-auth-token=bodytoken")
	req := httptest.NewRequest(http.MethodPost, "/testdomain", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Auth-Token", "headertoken")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/testdomain", resp.Header.Get("Location"))
}

func TestPostDomainLogin_missingToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	router, keystoneMock, _ := setupTest(t, ctrl)

	keystoneMock.EXPECT().AuthenticateRequest(test.MatchContext(), gomock.Any(), true).
		Return(nil, keystone.NewAuthenticationError(keystone.StatusMissingCredentials, "no credentials"))

	req := httptest.NewRequest(http.MethodPost, "/testdomain", http.NoBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}
