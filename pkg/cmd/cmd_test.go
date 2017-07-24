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
	"github.com/golang/mock/gomock"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/test"
	"time"
)

type testReporter struct {
	gomock.TestReporter
}

func (r testReporter) Errorf(format string, args ...interface{}) {
	panic(fmt.Errorf(format, args))
}

func (r testReporter) Fatalf(format string, args ...interface{}) {
	panic(fmt.Errorf(format, args))
}

func setupTest(controller *gomock.Controller) (keystone.Driver, *storage.MockDriver) {
	// set mandatory parameters
	maiaURL = "dummy"
	auth.UserID = "user_id"
	auth.Password = "password"
	auth.Scope.ProjectID = "12345"
	outputFormat = ""
	starttime = ""
	endtime = ""
	stepsize = 0
	columns = ""

	// create dummy keystone and storage mock
	keystone := keystone.Mock()
	storage := storage.NewMockDriver(controller)

	setKeystoneInstance(keystone)
	setStorageInstance(storage)

	return keystone, storage
}

// HTTP based tests

func ExampleSnapshot() {
	t := testReporter{}
	ctrl := gomock.NewController(&t)
	defer ctrl.Finish()

	_, storageMock := setupTest(ctrl)

	outputFormat = "vAlues"
	selector = "vmware_name=\"win_cifs_13\""
	storageMock.EXPECT().Federate([]string{"{" + selector + "}"}, storage.PlainText).Return(test.HTTPResponseFromFile("fixtures/federate.txt"), nil)

	snapshotCmd.RunE(snapshotCmd, []string{})
	// Output:
	// # TYPE vcenter_cpu_costop_summation untyped
	// vcenter_cpu_costop_summation{component="vcenter-exporter-vc-a-0",instance="100.65.0.252:9102",instance_uuid="3b32f415-c953-40b9-883d-51321611a7d4",job="endpoints",kubernetes_name="vcenter-exporter-vc-a-0",kubernetes_namespace="maia",metric_detail="3",project_id="12345",region="staging",service="metrics",system="openstack",vcenter_name="STAGINGA",vcenter_node="10.44.2.40",vmware_name="win_cifs_13"} 0 1500291187275
}

func ExampleSeries() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	_, storageMock := setupTest(ctrl)

	selector = "component!=\"\""
	starttime = "2017-07-01T20:10:30.781Z"
	endtime = "2017-07-02T04:00:00.000Z"
	outputFormat = "jsoN"

	storageMock.EXPECT().Series([]string{"{" + selector + "}"}, starttime, endtime, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/Series.json"), nil)

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

func ExampleLabelValues_json() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	_, storageMock := setupTest(ctrl)

	labelName := "component"
	outputFormat = "jSon"

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

	_, storageMock := setupTest(ctrl)

	labelName := "component"
	outputFormat = "VaLueS"

	storageMock.EXPECT().LabelValues(labelName, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/label_values.json"), nil)

	labelValuesCmd.RunE(labelValuesCmd, []string{labelName})

	// Output:
	// objectstore
}

func ExampleQuery_json() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	_, storageMock := setupTest(ctrl)

	timestamp = "2017-07-01T20:10:30.781Z"
	timeoutStr := "1440s"
	timeout, _ = time.ParseDuration(timeoutStr)
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "jsoN"

	storageMock.EXPECT().Query(query, timestamp, timeoutStr, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/Query.json"), nil)

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

	_, storageMock := setupTest(ctrl)

	timestamp = "2017-07-01T20:10:30.781Z"
	timeoutStr := "1440s"
	timeout, _ = time.ParseDuration(timeoutStr)
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "TaBle"

	storageMock.EXPECT().Query(query, timestamp, timeoutStr, storage.JSON).Return(test.HTTPResponseFromFile("fixtures/Query.json"), nil)

	queryCmd.RunE(queryCmd, []string{query})

	// Output:
	// __timestamp__ __value__
	// 2017-07-03T09:26:23.997+02:00 0
}

func ExampleQuery_rangeJSON() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	_, storageMock := setupTest(ctrl)

	starttime = "2017-07-01T20:10:30.781Z"
	endtime = "2017-07-02T04:00:00.000Z"
	stepsizeStr := "300s"
	stepsize, _ = time.ParseDuration(stepsizeStr)
	timeoutStr := "90s"
	timeout, _ = time.ParseDuration(timeoutStr)
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "jsoN"

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

	_, storageMock := setupTest(ctrl)

	starttime = "2017-07-01T20:10:30.781Z"
	endtime = "2017-07-02T04:00:00.000Z"
	stepsizeStr := "300s"
	stepsize, _ = time.ParseDuration(stepsizeStr)
	timeoutStr := "90s"
	timeout, _ = time.ParseDuration(timeoutStr)
	query := "sum(blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "tablE"

	storageMock.EXPECT().QueryRange(query, starttime, endtime, stepsizeStr, timeoutStr, "application/json").Return(test.HTTPResponseFromFile("fixtures/query_range_values.json"), nil)

	queryCmd.RunE(queryCmd, []string{query})

	// Output:
	// 2017-07-13T22:10:00+02:00 2017-07-13T22:15:00+02:00
	// 0 1
}

func ExampleQuery_rangeSeriesTable() {
	t := testReporter{}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	_, storageMock := setupTest(ctrl)

	starttime = "2017-07-22T20:10:00.000+02:00"
	endtime = "2017-07-22T20:20:00.000+02:00"
	stepsizeStr := "300s"
	stepsize, _ = time.ParseDuration(stepsizeStr)
	timeoutStr := "90s"
	timeout, _ = time.ParseDuration(timeoutStr)
	query := "blackbox_api_status_gauge{check=~\"keystone\"})"
	outputFormat = "tablE"
	columns = "region,check,instance"

	storageMock.EXPECT().QueryRange(query, starttime, endtime, stepsizeStr, timeoutStr, "application/json").Return(test.HTTPResponseFromFile("fixtures/query_range_series.json"), nil)

	queryCmd.RunE(queryCmd, []string{query})

	// Output:
	// check instance region 2017-07-22T22:10:00+02:00 2017-07-22T22:15:00+02:00 2017-07-22T22:20:00+02:00
	// keystone 100.64.0.102:9102 staging 0 1 0
}
