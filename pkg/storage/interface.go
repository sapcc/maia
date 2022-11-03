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

package storage

import (
	"encoding/json"
	"fmt"
	"github.com/prometheus/common/model"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"net/http"
)

const (
	// P8SProtoBuf is the native protocol (preferred)
	P8SProtoBuf string = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.7,text/plain;version=0.0.4;q=0.3,*/*;q=0.1"
	// PlainText is used for readable federate output
	PlainText = "text/plain; version=0.0.4"
	// JSON is used to obtain output in JSON (--format json)
	JSON = "application/json"
)

// Status contains Prometheus status strings
type Status string

const (
	// StatusSuccess means success
	StatusSuccess Status = "success"
	// StatusError means error
	StatusError = "error"
)

// ErrorType enumerates different Prometheus error types
type ErrorType string

const (
	// ErrorNone means no error
	ErrorNone ErrorType = ""
	// ErrorTimeout means that a timeout occurred while processing the request
	ErrorTimeout = "timeout"
	// ErrorCanceled means that the query was cancelled (to protect the service from malicious requests)
	ErrorCanceled = "canceled"
	// ErrorExec means unspecified error happened during query execution
	ErrorExec = "execution"
	// ErrorBadData means the API parameters where invalid
	ErrorBadData = "bad_data"
	// ErrorInternal means some unspecified internal error happened
	ErrorInternal = "internal"
)

// Response encapsulates a generic response of a Prometheus API
type Response struct {
	Status    Status        `json:"status"`
	Data      []interface{} `json:"data,omitempty"`
	ErrorType ErrorType     `json:"errorType,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// SeriesResponse encapsulates a response to the /series API of Prometheus
type SeriesResponse struct {
	Status    Status           `json:"status"`
	Data      []model.LabelSet `json:"data,omitempty"`
	ErrorType ErrorType        `json:"errorType,omitempty"`
	Error     string           `json:"error,omitempty"`
}

// LabelValuesResponse encapsulates a response to the /label/values API of Prometheus
type LabelValuesResponse struct {
	Status Status            `json:"status"`
	Data   model.LabelValues `json:"data"`
}

// QueryResponse contains the response from a call to query or query_range
type QueryResponse struct {
	Status    Status      `json:"status"`
	Data      QueryResult `json:"data,omitempty"`
	ErrorType ErrorType   `json:"errorType,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// QueryResult contains the actual result of a query or query_range call
type QueryResult struct {
	Type   model.ValueType `json:"resultType"`
	Result interface{}     `json:"result"`

	// The decoded value.
	Value model.Value
}

// UnmarshalJSON contains a custom unmarshaller
func (qr *QueryResult) UnmarshalJSON(b []byte) error {
	v := struct {
		Type   model.ValueType `json:"resultType"`
		Result json.RawMessage `json:"result"`
	}{}

	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}

	switch v.Type {
	case model.ValScalar:
		var sv model.Scalar
		err = json.Unmarshal(v.Result, &sv)
		qr.Value = &sv

	case model.ValVector:
		var vv model.Vector
		err = json.Unmarshal(v.Result, &vv)
		qr.Value = vv

	case model.ValMatrix:
		var mv model.Matrix
		err = json.Unmarshal(v.Result, &mv)
		qr.Value = mv

	default:
		err = fmt.Errorf("unexpected value type %q", v.Type)
	}
	return err
}

// Driver is an interface that wraps the underlying event storage mechanism.
// Because it is an interface, the real implementation can be mocked away in unit tests.
// For pragmatic reasons the HTTP response from the underlying storage service is passed
// on unchanged. For most API operations, Maia does not have to transform the response and that way
// we can avoid an entire in-memory unmarshal-marshal cycle.
type Driver interface {
	/********** requests to Prometheus **********/
	Federate(selectors []string, acceptContentType string) (*http.Response, error)
	Query(query, time, timeout string, acceptContentType string) (*http.Response, error)
	QueryRange(query, start, end, step, timeout string, acceptContentType string) (*http.Response, error)
	Series(match []string, start, end string, acceptContentType string) (*http.Response, error)
	LabelValues(name string, acceptContentType string) (*http.Response, error)
	DelegateRequest(request *http.Request) (*http.Response, error)
}

// NewPrometheusDriver is a factory method which chooses the right driver implementation based on configuration settings
func NewPrometheusDriver(prometheusAPIURL string, customHeader map[string]string) Driver {
	driverName := viper.GetString("maia.storage_driver")
	switch driverName {
	case "prometheus":
		driver := Prometheus(prometheusAPIURL, customHeader)
		if driver == nil {
			util.LogFatal("Couldn't initialize Prometheus storage driver with given endpoint: \"%s\"", prometheusAPIURL)
			return nil
		}
		util.LogInfo("Using API server at: \"%s\"", prometheusAPIURL)

		return driver
	default:
		panic(fmt.Errorf("invalid service.storage_driver setting: %s", driverName))
	}
}
