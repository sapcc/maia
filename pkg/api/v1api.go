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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/common/model"
	"github.com/spf13/viper"

	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/util"
)

// class for Prometheus v1 API provider implementation
type v1Provider struct {
	keystone keystone.Driver
	storage  storage.Driver
}

// NewV1Handler creates a http.Handler that serves the Maia v1 API.
// It also returns the VersionData for this API version which is needed for the
// version advertisement on "GET /".
func NewV1Handler(keystoneDriver keystone.Driver, storageDriver storage.Driver) http.Handler {
	r := mux.NewRouter()
	p := &v1Provider{
		keystone: keystoneDriver,
		storage:  storageDriver,
	}

	// tenant-aware query
	r.Methods(http.MethodGet).Path("/query").HandlerFunc(authorize(
		observeDuration(observeResponseSize(p.Query, "query"), "query"),
		false,
		"metric:show"))
	// tenant-aware query range
	r.Methods(http.MethodGet).Path("/query_range").HandlerFunc(authorize(
		observeDuration(observeResponseSize(p.QueryRange, "query_range"), "query_range"),
		false,
		"metric:show"))
	// tenant-aware label value lists
	r.Methods(http.MethodGet).Path("/label/{name}/values").HandlerFunc(authorize(observeDuration(observeResponseSize(p.LabelValues, "label_values"), "label_values"), false, "metric:list"))
	// tenant-aware series metadata
	r.Methods(http.MethodGet).Path("/series").HandlerFunc(authorize(observeDuration(observeResponseSize(p.Series, "series"), "series"), false, "metric:list"))

	return r
}

func (p *v1Provider) Query(w http.ResponseWriter, req *http.Request) {
	labelKey, labelValue := scopeToLabelConstraint(req, p.keystone)

	queryParams := req.URL.Query()
	newQuery, err := util.AddLabelConstraintToExpression(queryParams.Get("query"), labelKey, labelValue)
	if err != nil {
		ReturnPromError(w, err, http.StatusBadRequest)
		return
	}

	resp, err := p.storage.Query(newQuery, queryParams.Get("time"), queryParams.Get("timeout"), req.Header.Get("Accept"))
	if err != nil {
		ReturnPromError(w, err, http.StatusServiceUnavailable)
		return
	}

	ReturnResponse(w, resp)
}

func (p *v1Provider) QueryRange(w http.ResponseWriter, req *http.Request) {
	labelKey, labelValue := scopeToLabelConstraint(req, p.keystone)

	queryParams := req.URL.Query()
	newQuery, err := util.AddLabelConstraintToExpression(queryParams.Get("query"), labelKey, labelValue)
	if err != nil {
		ReturnPromError(w, err, http.StatusBadRequest)
		return
	}

	resp, err := p.storage.QueryRange(newQuery, queryParams.Get("start"), queryParams.Get("end"), queryParams.Get("step"), queryParams.Get("timeout"), req.Header.Get("Accept"))
	if err != nil {
		ReturnPromError(w, err, http.StatusServiceUnavailable)
		return
	}

	ReturnResponse(w, resp)
}

// LabelValues utilizes the query range API in order to implement a tenant-aware list.
// This is a complex operation.
func (p *v1Provider) LabelValues(w http.ResponseWriter, req *http.Request) {
	name := model.LabelName(mux.Vars(req)["name"])
	// do not list label values from series older than maia.label_value_ttl
	ttl, err := time.ParseDuration(viper.GetString("maia.label_value_ttl"))
	if err != nil {
		ReturnPromError(w, errors.New("invalid Maia configuration (maia.label_value_ttl)"), http.StatusInternalServerError)
		return
	}

	// build project_id constraint using project hierarchy
	labelKey, labelValues := scopeToLabelConstraint(req, p.keystone)
	// make a broad range query and aggregate by requested label. Use count() as cheap aggregation function.
	query, err := util.AddLabelConstraintToExpression("count({"+string(name)+"!=\"\"}) BY ("+string(name)+")", labelKey, labelValues)
	if err != nil {
		ReturnPromError(w, err, http.StatusBadRequest)
	}

	start := time.Now().Add(-ttl)
	end := time.Now()
	// choose step-size so long that only two values are returned (oldest and latest)
	step := viper.GetString("maia.label_value_ttl")
	resp, err := p.storage.QueryRange(query, start.Format(time.RFC3339), end.Format(time.RFC3339), step, "", req.Header.Get("Accept"))
	if err != nil {
		ReturnPromError(w, err, http.StatusBadGateway)
		return
	}

	// read the complete result into memory
	// could this be avoided (streaming like in Java)?
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		ReturnPromError(w, err, resp.StatusCode)
		return
	}

	// unmarshal
	var sr storage.QueryResponse
	err = json.Unmarshal(buf, &sr)
	if err != nil {
		ReturnPromError(w, err, http.StatusInternalServerError)
		return
	}
	matrix := sr.Data.Value.(model.Matrix) //nolint:errcheck

	// take just the label values from the query result
	var result storage.LabelValuesResponse
	result.Status = sr.Status
	result.Data = make(model.LabelValues, 0, len(matrix))
	for k := range matrix {
		metric := matrix[k]
		if metric != nil {
			result.Data = append(result.Data, metric.Metric[name])
		}
	}
	// sort the stuff (it's often on the UI)
	sort.Sort(result.Data)

	ReturnJSON(w, 200, &result)
}

func (p *v1Provider) Series(w http.ResponseWriter, req *http.Request) {
	selectors, err := buildSelectors(req, p.keystone)
	if err != nil {
		ReturnPromError(w, err, http.StatusBadRequest)
		return
	}
	queryParams := req.URL.Query()
	resp, err := p.storage.Series(*selectors, queryParams.Get("start"), queryParams.Get("end"), req.Header.Get("Accept"))
	if err != nil {
		ReturnPromError(w, err, http.StatusBadGateway)
		return
	}

	ReturnResponse(w, resp)
}

func (p *v1Provider) Labels(w http.ResponseWriter, req *http.Request) {
	queryParams := req.URL.Query()
	start := queryParams.Get("start")
	end := queryParams.Get("end")
	match := queryParams["match[]"]

	resp, err := p.storage.Labels(start, end, match, req.Header.Get("Accept"))
	if err != nil {
		ReturnPromError(w, err, http.StatusServiceUnavailable)
		return
	}

	ReturnResponse(w, resp)
}
