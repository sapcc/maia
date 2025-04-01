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

package cmd

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	policy "github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud/v2"
	"go.uber.org/mock/gomock"

	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/test"
)

type testReporter struct {
	gomock.TestReporter
}

func (r testReporter) Errorf(format string, args ...interface{}) {
	panic(fmt.Errorf(format, args...))
}

func (r testReporter) Fatalf(format string, args ...interface{}) {
	panic(fmt.Errorf(format, args...))
}

func setupTest(controller *gomock.Controller) (keystoneDriver *keystone.MockDriver, storageDriver *storage.MockDriver) {
	// simulate command parameters
	authType = ""
	outputFormat = ""
	starttime = ""
	endtime = ""
	tzLocation = time.UTC
	stepsize = 0
	columns = ""
	maiaURL = ""
	promURL = ""

	// set mandatory parameters
	auth = gophercloud.AuthOptions{
		IdentityEndpoint: "",
		Username:         "username",
		DomainName:       "domainname",
		Password:         "testwd",
		Scope: &gophercloud.AuthScope{
			ProjectID: "12345"}}

	// create dummy keystone and storage mock
	keystoneDriver = keystone.NewMockDriver(controller)
	storageDriver = storage.NewMockDriver(controller)

	setKeystoneInstance(keystoneDriver)
	setStorageInstance(storageDriver)

	return keystoneDriver, storageDriver
}

func expectAuth(keystoneMock *keystone.MockDriver) {
	ctx := context.Background()
	keystoneMock.EXPECT().Authenticate(ctx, gophercloud.AuthOptions{IdentityEndpoint: auth.IdentityEndpoint, Username: auth.Username, UserID: auth.UserID,
		Password: auth.Password, DomainName: auth.DomainName, Scope: auth.Scope}).Return(&policy.Context{Request: map[string]string{"username": auth.Username,
		"password": auth.Password, "user_domain_name": "domainname", "project_id": auth.Scope.ProjectID},
		Auth: map[string]string{"project_id": auth.Scope.ProjectID}, Roles: []string{"monitoring_viewer"}}, "http://localhost:9091", nil)
	// call this explicitly since the mocked storage does not
	fetchToken(ctx)
}

// HTTP based tests

func ExampleSnapshot() {
	t := testReporter{}
	ctrl := gomock.NewController(&t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	outputFormat = "vAlue"
	selector = "vmware_name=\"win_cifs_13\""

	expectAuth(keystoneMock)
	storageMock.EXPECT().Federate([]string{"{" + selector + "}"}, storage.PlainText).Return(test.HTTPResponseFromFile("fixtures/federate.txt"), nil)

	snapshotCmd.RunE(snapshotCmd, []string{}) //nolint:errcheck

	// Output:
	// # TYPE vcenter_cpu_costop_summation untyped
	// vcenter_cpu_costop_summation{component="vcenter-exporter-vc-a-0",instance="100.65.0.252:9102",instance_uuid="3b32f415-c953-40b9-883d-51321611a7d4",job="endpoints",kubernetes_name="vcenter-exporter-vc-a-0",kubernetes_namespace="maia",metric_detail="3",project_id="12345",region="staging",service="metrics",system="openstack",vcenter_name="STAGINGA",vcenter_node="10.44.2.40",vmware_name="win_cifs_13"} 0 1500291187275
}

func ExampleSeries_json() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	selector = "component!=\"\""
	starttime = "2017-07-01T20:10:30.781Z"
	endtime = "2017-07-02T04:00:00.000Z"
	outputFormat = "jsoN"

	expectAuth(keystoneMock)
	storageMock.EXPECT().Series([]string{"{" + selector + "}"}, starttime, endtime, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/series.json"), nil)

	seriesCmd.RunE(seriesCmd, []string{}) //nolint:errcheck

	// Output:
	// {
	//   "status": "success",
	//   "data": [
	//     {
	//       "__name__": "up",
	//       "component": "objectstore",
	//       "instance": "100.64.1.159:9102",
	//       "job": "endpoints",
	//       "kubernetes_name": "swift-proxy-cluster-3",
	//       "kubernetes_namespace": "swift",
	//       "os_cluster": "cluster-3",
	//       "region": "staging",
	//       "system": "openstack"
	//     }
	//   ]
	// }
}

func ExampleSeries_table() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	selector = "component!=\"\""
	starttime = "2017-07-01T20:10:30.781Z"
	endtime = "2017-07-02T04:00:00.000Z"
	outputFormat = "table"

	expectAuth(keystoneMock)
	storageMock.EXPECT().Series([]string{"{" + selector + "}"}, starttime, endtime, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/series.json"), nil)

	seriesCmd.RunE(seriesCmd, []string{}) //nolint:errcheck

	// Output:
	// __name__ component instance job kubernetes_name kubernetes_namespace os_cluster region system
	// up objectstore 100.64.1.159:9102 endpoints swift-proxy-cluster-3 swift cluster-3 staging openstack
}

func ExampleLabelValues_json() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	labelName := "component"
	outputFormat = "jSon"

	expectAuth(keystoneMock)
	storageMock.EXPECT().LabelValues(labelName, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/label_values.json"), nil)

	labelValuesCmd.RunE(labelValuesCmd, []string{labelName}) //nolint:errcheck

	// Output:
	// {
	//   "Status": "success",
	//   "data": [
	//     "objectstore"
	//   ]
	// }
}

func ExampleLabelValues_values() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	labelName := "component"
	outputFormat = "VaLue"

	expectAuth(keystoneMock)
	storageMock.EXPECT().LabelValues(labelName, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/label_values.json"), nil)

	labelValuesCmd.RunE(labelValuesCmd, []string{labelName}) //nolint:errcheck

	// Output:
	// objectstore
}

func ExampleMetricNames_values() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	outputFormat = "valuE"

	expectAuth(keystoneMock)
	storageMock.EXPECT().LabelValues("__name__", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/metric_names.json"), nil)

	metricNamesCmd.RunE(metricNamesCmd, []string{}) //nolint:errcheck

	// Output:
	// vcenter_cpu_costop_summation
	// vcenter_cpu_demand_average
	// vcenter_cpu_idle_summation
	// vcenter_cpu_latency_average
}

func ExampleQuery_json() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	timestamp = "2017-07-01T20:10:30.781Z"
	timeoutStr := "1440s"
	timeout, _ = time.ParseDuration(timeoutStr) //nolint:errcheck
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "jsoN"

	expectAuth(keystoneMock)
	storageMock.EXPECT().Query(query, timestamp, timeoutStr, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query.json"), nil)

	queryCmd.RunE(queryCmd, []string{query}) //nolint:errcheck

	// Output:
	// {
	//   "status": "success",
	//   "data": {
	//     "resultType": "vector",
	//     "result": [
	//       {
	//         "metric": {},
	//         "value": [
	//           1499066783.997,
	//           "0"
	//         ]
	//       }
	//     ]
	//   }
	// }
}

func ExampleQuery_table() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	timestamp = "2017-07-03T07:26:23.997Z"
	timeoutStr := "1440s"
	timeout, _ = time.ParseDuration(timeoutStr) //nolint:errcheck
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "TaBle"

	expectAuth(keystoneMock)
	storageMock.EXPECT().Query(query, timestamp, timeoutStr, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query.json"), nil)

	queryCmd.RunE(queryCmd, []string{query}) //nolint:errcheck

	// Output:
	// __timestamp__ __value__
	// 2017-07-03T07:26:23.997Z 0
}

func ExampleQuery_tableColumns() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	timestamp = "2019-05-09T12:00:10.724Z"
	timeoutStr := "1440s"
	timeout, _ = time.ParseDuration(timeoutStr) //nolint:errcheck
	query := "limes_domain_quota"
	outputFormat = "TaBle"
	columns = "domain"

	expectAuth(keystoneMock)
	storageMock.EXPECT().Query(query, timestamp, timeoutStr, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query2.json"), nil)

	queryCmd.RunE(queryCmd, []string{query}) //nolint:errcheck

	// Output:
	// domain __timestamp__ __value__
	// monsoon3 2019-05-09T12:00:10.724Z 54975581388800
	// monsoon3 2019-05-09T12:00:10.724Z 11240
}

func ExampleQuery_rangeJSON() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	starttime = "2017-07-13T20:10:30.781Z"
	endtime = "2017-07-13T20:15:00.781Z"
	stepsizeStr := "300s"
	stepsize, _ = time.ParseDuration(stepsizeStr) //nolint:errcheck
	timeoutStr := "90s"
	timeout, _ = time.ParseDuration(timeoutStr) //nolint:errcheck
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "jsoN"

	expectAuth(keystoneMock)
	storageMock.EXPECT().QueryRange(query, starttime, endtime, stepsizeStr, timeoutStr, "application/json").Return(test.HTTPResponseFromFile("fixtures/query_range_values.json"), nil)

	queryCmd.RunE(queryCmd, []string{query}) //nolint:errcheck

	// Output:
	// {
	//   "status": "success",
	//   "data": {
	//     "resultType": "matrix",
	//     "result": [
	//       {
	//         "metric": {},
	//         "values": [
	//           [
	//             1499976630.781,
	//             "0"
	//           ],
	//           [
	//             1499976930.781,
	//             "1"
	//           ]
	//         ]
	//       }
	//     ]
	//   }
	// }
}

func ExampleQuery_rangeValuesTable() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	starttime = "2017-07-13T20:10:30.000Z"
	endtime = "2017-07-13T20:15:00.000Z"
	stepsizeStr := "300s"
	stepsize, _ = time.ParseDuration(stepsizeStr) //nolint:errcheck
	timeoutStr := "90s"
	timeout, _ = time.ParseDuration(timeoutStr) //nolint:errcheck
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "tablE"

	expectAuth(keystoneMock)
	storageMock.EXPECT().QueryRange(query, starttime, endtime, stepsizeStr, timeoutStr, "application/json").Return(test.HTTPResponseFromFile("fixtures/query_range_values.json"), nil)

	queryCmd.RunE(queryCmd, []string{query}) //nolint:errcheck

	// Output:
	// 2017-07-13T20:10:00Z 2017-07-13T20:15:00Z
	// 0 1
}

func ExampleQuery_rangeSeriesTable() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	starttime = "2017-07-22T20:10:00.000Z"
	endtime = "2017-07-22T20:20:00.000Z"
	stepsizeStr := "300s"
	stepsize, _ = time.ParseDuration(stepsizeStr) //nolint:errcheck
	timeoutStr := "90s"
	timeout, _ = time.ParseDuration(timeoutStr) //nolint:errcheck
	query := "blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "tablE"
	columns = "region,check,instance"

	expectAuth(keystoneMock)
	storageMock.EXPECT().QueryRange(query, starttime, endtime, stepsizeStr, timeoutStr, "application/json").Return(test.HTTPResponseFromFile("fixtures/query_range_series.json"), nil)

	queryCmd.RunE(queryCmd, []string{query}) //nolint:errcheck

	// Output:
	// region check instance 2017-07-22T20:10:00Z 2017-07-22T20:15:00Z 2017-07-22T20:20:00Z
	// staging keystone 100.64.0.102:9102 0 1 0
}

// Authentication tests

func Test_Auth(t *testing.T) {
	tt := []struct {
		name          string
		tokenid       string
		authtype      string
		username      string
		userid        string
		password      string
		appcredid     string
		appcredname   string
		appcredsecret string
		expectpanic   bool
	}{
		{"passwithauthtype", "", "password", "", "testid", "testwd", "", "", "", false},
		{"passwithoutauthtype", "", "", "testname", "", "testwd", "", "", "", false},
		{"failusernameandid", "", "password", "testname", "testid", "testwd", "", "", "", true},
		{"tokenwithpasswithauthtype", "ABC", "token", "testname", "testid", "testwd", "", "", "", false},
		{"tokenwithpasswithoutauthtype", "ABC", "", "testname", "testid", "testwd", "", "", "", true},
		{"appcredidwithsecret", "", "v3applicationcredential", "", "", "", "testappcredid", "", "testappcredsecret", false},
		{"appcrednamewithusername", "", "v3applicationcredential", "testname", "", "", "", "testappcredname", "testappcredsecret", false},
		{"appcrednamewithoutusername", "", "v3applicationcredential", "", "", "", "", "testappcredname", "testappcredsecret", true},
		{"appcredidwithoutsecret", "", "v3applicationcredential", "testname", "", "", "testappcredid", "", "", true},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			paniced := authentication(tc.tokenid, tc.authtype, tc.username, tc.userid, tc.password, tc.appcredid, tc.appcredname, tc.appcredsecret)
			if paniced != tc.expectpanic {
				t.Errorf("Panic does not match desired result for test: %v", tc)
			}
		})
	}
}

func authentication(tokenid, authtype, username, userid, password, appcredid, appcredname, appcredsecret string) (paniced bool) {
	paniced = false
	ctx := context.Background()

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, r)
			paniced = true
		}
	}()

	tr := testReporter{}
	ctrl := gomock.NewController(&tr)
	defer ctrl.Finish()

	// simulate command parameters
	authType = authtype
	outputFormat = ""
	starttime = ""
	endtime = ""
	tzLocation = time.UTC
	stepsize = 0
	columns = ""
	maiaURL = ""
	promURL = ""

	scope := &gophercloud.AuthScope{
		ProjectID: "12345"}

	// set mandatory parameters
	auth = gophercloud.AuthOptions{
		IdentityEndpoint:            "",
		Username:                    username,
		UserID:                      userid,
		Password:                    password,
		ApplicationCredentialID:     appcredid,
		ApplicationCredentialName:   appcredname,
		ApplicationCredentialSecret: appcredsecret,
		TokenID:                     tokenid,
		Scope:                       scope}
	expectedAuth := auth

	switch authtype {
	case "v3applicationcredential":
		expectedAuth.Scope = nil
		expectedAuth.TokenID = ""
		expectedAuth.Password = ""
	case "token":
		expectedAuth.Username = ""
		expectedAuth.UserID = ""
		expectedAuth.Password = ""
	}

	// create dummy keystone and storage mock
	keystoneMock := keystone.NewMockDriver(ctrl)
	setKeystoneInstance(keystoneMock)
	keystoneMock.EXPECT().Authenticate(ctx, expectedAuth).Return(&policy.Context{
		Request: map[string]string{
			"user_id":                       auth.UserID,
			"project_id":                    "12345",
			"password":                      auth.Password,
			"application_credential_id":     auth.ApplicationCredentialID,
			"application_credential_name":   auth.ApplicationCredentialName,
			"application_credential_secret": auth.ApplicationCredentialSecret},
		Auth:  map[string]string{"project_id": auth.Scope.ProjectID},
		Roles: []string{"monitoring_viewer"},
	}, "http://localhost:9091", nil)
	fetchToken(ctx)

	return paniced
}
