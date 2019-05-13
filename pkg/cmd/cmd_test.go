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
	"fmt"
	"testing"
	"time"

	policy "github.com/databus23/goslo.policy"
	"github.com/golang/mock/gomock"
	"github.com/gophercloud/gophercloud"
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

func setupTest(controller *gomock.Controller) (*keystone.MockDriver, *storage.MockDriver) {
	// set mandatory parameters
	auth.IdentityEndpoint = ""
	auth.Username = "username"
	auth.UserID = "user_id"
	auth.Password = "testwd"
	authType = "password"
	auth.Scope.ProjectID = "12345"
	outputFormat = ""
	starttime = ""
	endtime = ""
	stepsize = 0
	columns = ""

	// create dummy keystone and storage mock
	keystone := keystone.NewMockDriver(controller)
	storage := storage.NewMockDriver(controller)
	tzLocation = time.UTC

	setKeystoneInstance(keystone)
	setStorageInstance(storage)

	return keystone, storage
}

func expectAuth(keystoneMock *keystone.MockDriver) {
	keystoneMock.EXPECT().Authenticate(gophercloud.AuthOptions{IdentityEndpoint: auth.IdentityEndpoint, Username: auth.Username, UserID: auth.UserID, Password: auth.Password, DomainName: auth.DomainName, Scope: auth.Scope}).Return(&policy.Context{Request: map[string]string{"user_id": auth.UserID,
		"project_id": auth.Scope.ProjectID, "password": auth.Password}, Auth: map[string]string{"project_id": auth.Scope.ProjectID}, Roles: []string{"monitoring_viewer"}}, "http://localhost:9091", nil)
	// call this explicitly since the mocked storage does not
	fetchToken()
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

	snapshotCmd.RunE(snapshotCmd, []string{})
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

	seriesCmd.RunE(seriesCmd, []string{})

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

	seriesCmd.RunE(seriesCmd, []string{})

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

	labelValuesCmd.RunE(labelValuesCmd, []string{labelName})

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

	labelValuesCmd.RunE(labelValuesCmd, []string{labelName})

	// Output:
	// objectstore
}

func ExampleMetricNames_values() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	maiaURL = "http://localhost:9091"
	keystoneMock, storageMock := setupTest(ctrl)

	outputFormat = "valuE"

	expectAuth(keystoneMock)
	storageMock.EXPECT().LabelValues("__name__", storage.JSON).Return(test.HTTPResponseFromFile("fixtures/metric_names.json"), nil)

	metricNamesCmd.RunE(metricNamesCmd, []string{})

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
	timeout, _ = time.ParseDuration(timeoutStr)
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "jsoN"

	expectAuth(keystoneMock)
	storageMock.EXPECT().Query(query, timestamp, timeoutStr, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query.json"), nil)

	queryCmd.RunE(queryCmd, []string{query})

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
	timeout, _ = time.ParseDuration(timeoutStr)
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "TaBle"

	expectAuth(keystoneMock)
	storageMock.EXPECT().Query(query, timestamp, timeoutStr, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/query.json"), nil)

	queryCmd.RunE(queryCmd, []string{query})

	// Output:
	// __timestamp__ __value__
	// 2017-07-03T07:26:23.997Z 0
}

func ExampleQuery_rangeJSON() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keystoneMock, storageMock := setupTest(ctrl)

	starttime = "2017-07-13T20:10:30.781Z"
	endtime = "2017-07-13T20:15:00.781Z"
	stepsizeStr := "300s"
	stepsize, _ = time.ParseDuration(stepsizeStr)
	timeoutStr := "90s"
	timeout, _ = time.ParseDuration(timeoutStr)
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "jsoN"

	expectAuth(keystoneMock)
	storageMock.EXPECT().QueryRange(query, starttime, endtime, stepsizeStr, timeoutStr, "application/json").Return(test.HTTPResponseFromFile("fixtures/query_range_values.json"), nil)

	queryCmd.RunE(queryCmd, []string{query})

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
	stepsize, _ = time.ParseDuration(stepsizeStr)
	timeoutStr := "90s"
	timeout, _ = time.ParseDuration(timeoutStr)
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "tablE"

	expectAuth(keystoneMock)
	storageMock.EXPECT().QueryRange(query, starttime, endtime, stepsizeStr, timeoutStr, "application/json").Return(test.HTTPResponseFromFile("fixtures/query_range_values.json"), nil)

	queryCmd.RunE(queryCmd, []string{query})

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
	stepsize, _ = time.ParseDuration(stepsizeStr)
	timeoutStr := "90s"
	timeout, _ = time.ParseDuration(timeoutStr)
	query := "blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "tablE"
	columns = "region,check,instance"

	expectAuth(keystoneMock)
	storageMock.EXPECT().QueryRange(query, starttime, endtime, stepsizeStr, timeoutStr, "application/json").Return(test.HTTPResponseFromFile("fixtures/query_range_series.json"), nil)

	queryCmd.RunE(queryCmd, []string{query})

	// Output:
	// check instance region 2017-07-22T20:10:00Z 2017-07-22T20:15:00Z 2017-07-22T20:20:00Z
	// keystone 100.64.0.102:9102 staging 0 1 0
}

// Authentication tests

func TestAuthenticate_authWithTokenWithoutAuthtype(t *testing.T) {
	passed := false

	defer func() {
		if r := recover(); r != nil {
			// test passes
		}
		passed = true
	}()

	tr := testReporter{}
	ctrl := gomock.NewController(&tr)
	defer ctrl.Finish()

	// set mandatory parameters
	auth.IdentityEndpoint = ""
	auth.TokenID = "ABC"
	auth.Username = "username"
	auth.UserID = "user_id"
	auth.Password = "testwd"
	//authType = "token"
	auth.Scope.ProjectID = "12345"
	outputFormat = ""
	starttime = ""
	endtime = ""
	stepsize = 0
	columns = ""

	// create dummy keystone and storage mock
	keystoneMock := keystone.NewMockDriver(ctrl)
	setKeystoneInstance(keystoneMock)
	keystoneMock.EXPECT().Authenticate(gophercloud.AuthOptions{
		IdentityEndpoint: auth.IdentityEndpoint,
		Username:         auth.Username,
		UserID:           auth.UserID,
		Password:         auth.Password,
		DomainName:       auth.DomainName,
		Scope:            auth.Scope,
	}).Return(&policy.Context{
		Request: map[string]string{
			"user_id":    auth.UserID,
			"project_id": auth.Scope.ProjectID,
			"password":   auth.Password},
		Auth:  map[string]string{"project_id": auth.Scope.ProjectID},
		Roles: []string{"monitoring_viewer"},
	}, "http://localhost:9091", nil)

	fetchToken()

	if !passed {
		t.Fail()
	}
}

func Test_Auth(t *testing.T) {
	tt := []struct {
		name        string
		tokenid     string
		authtype    string
		username    string
		userid      string
		password    string
		expectpanic bool
	}{
		{"tokenwithauthtype", "ABC", "token", "", "", "", false},
		{"tokenwithoutauthtype", "ABC", "token", "", "", "", false},
		{"tokenwithpasswithauthtype", "ABC", "token", "testname", "testid", "testwd", false},
		{"tokenwithpasswithoutauthtype", "ABC", "", "testname", "testid", "testwd", true},
		{"passwithauthtype", "", "password", "testname", "testid", "testwd", false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			paniced := authentication(tc.tokenid, tc.authtype, tc.username, tc.userid, tc.password)
			if paniced != tc.expectpanic {
				t.Errorf("Panic does not match desired result for test: %s", tc.name)
			}
		})
	}

}

func authentication(tokenid, authtype, username, userid, password string) (paniced bool) {
	paniced = false

	defer func() {
		if r := recover(); r != nil {
			paniced = true
		}

	}()

	tr := testReporter{}
	ctrl := gomock.NewController(&tr)
	defer ctrl.Finish()

	// set mandatory parameters
	auth.IdentityEndpoint = ""
	auth.TokenID = tokenid
	auth.Username = username
	auth.UserID = userid
	auth.Password = password
	authType = authtype
	auth.Scope.ProjectID = "12345"
	outputFormat = ""
	starttime = ""
	endtime = ""
	stepsize = 0
	columns = ""

	// create dummy keystone and storage mock
	keystoneMock := keystone.NewMockDriver(ctrl)
	setKeystoneInstance(keystoneMock)
	keystoneMock.EXPECT().Authenticate(gophercloud.AuthOptions{
		IdentityEndpoint: auth.IdentityEndpoint,
		Username:         auth.Username,
		UserID:           auth.UserID,
		Password:         auth.Password,
		DomainName:       auth.DomainName,
		Scope:            auth.Scope,
	}).Return(&policy.Context{
		Request: map[string]string{
			"user_id":    auth.UserID,
			"project_id": auth.Scope.ProjectID,
			"password":   auth.Password},
		Auth:  map[string]string{"project_id": auth.Scope.ProjectID},
		Roles: []string{"monitoring_viewer"},
	}, "http://localhost:9091", nil)

	fetchToken()

	return paniced
}
