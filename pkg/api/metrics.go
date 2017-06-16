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
	"net/http"

	"encoding/json"
	"errors"
	"github.com/gorilla/mux"
	"github.com/prometheus/common/model"
	"github.com/sapcc/maia/pkg/maia"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
)

// MetricList is the model for JSON returned by the ListMetrics API call
type MetricList struct {
	NextURL string         `json:"next,omitempty"`
	PrevURL string         `json:"previous,omitempty"`
	Metrics []*maia.Metric `json:"metrics"`
}

//ListMetrics handles GET /v1/metrics.
func (p *v1Provider) ListMetrics(w http.ResponseWriter, req *http.Request, projectID string) {
	util.LogDebug("api.ListMetrics")
	response, err := p.storage.ListMetrics(projectID)
	if err != nil {
		util.LogError("Could not get metrics for project %s", projectID)
		ReturnError(w, err, 503)
		return
	}

	ReturnResponse(w, response)
}

func (p *v1Provider) Query(w http.ResponseWriter, req *http.Request, projectID string) {
	queryParams := req.URL.Query()
	newQuery, err := util.AddLabelConstraintToExpression(queryParams.Get("query"), "project_id", projectID)
	if err != nil {
		ReturnError(w, err, 400)
		return
	}

	util.LogInfo(newQuery)
	resp, err := p.storage.Query(newQuery, queryParams.Get("time"), queryParams.Get("timeout"))
	if err != nil {
		ReturnError(w, err, 503)
		return
	}

	ReturnResponse(w, resp)
}

func (p *v1Provider) QueryRange(w http.ResponseWriter, req *http.Request, projectID string) {
	queryParams := req.URL.Query()
	newQuery, err := util.AddLabelConstraintToExpression(queryParams.Get("query"), "project_id", projectID)
	if err != nil {
		ReturnError(w, err, 400)
		return
	}

	resp, err := p.storage.QueryRange(newQuery, queryParams.Get("start"), queryParams.Get("end"), queryParams.Get("step"), queryParams.Get("timeout"))
	if err != nil {
		ReturnError(w, err, 503)
		return
	}

	ReturnResponse(w, resp)
}

type seriesResponse struct {
	Status    status           `json:"status"`
	Data      []model.LabelSet `json:"data,omitempty"`
	ErrorType errorType        `json:"errorType,omitempty"`
	Error     string           `json:"error,omitempty"`
}

type labelValuesResponse struct {
	Status status             `json:"status"`
	Data   []model.LabelValue `json:"data"`
}

func (p *v1Provider) LabelValues(w http.ResponseWriter, req *http.Request, projectID string) {
	name := model.LabelName(mux.Vars(req)["name"])
	// do not list label values from series older than maia.label_value_ttl
	ttl, err := time.ParseDuration(viper.GetString("maia.label_value_ttl"))
	if err != nil {
		ReturnError(w, errors.New("Invalid Maia configuration (maia.label_value_ttl)"), 500)
		return
	}

	start := time.Now().Add(-ttl)
	end := time.Now()
	resp, err := p.storage.Series([]string{"{project_id=\"" + projectID + "\"," + string(name) + "!=\"\"}"}, start.Format(time.RFC3339), end.Format(time.RFC3339))
	if err != nil {
		ReturnError(w, err, 503)
		return
	}

	// extract label values from series
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ReturnError(w, err, resp.StatusCode)
		return
	}

	var sr seriesResponse
	if err := json.Unmarshal(buf, &sr); err != nil {
		ReturnError(w, err, 500)
		return
	}
	// collect unique values from 1000x bigger :( series list
	unique := map[model.LabelValue]bool{}
	for _, lset := range sr.Data {
		v := lset[name]
		unique[v] = true
	}
	// transform into expected result type
	var result labelValuesResponse
	result.Status = sr.Status
	result.Data = make([]model.LabelValue, 0)
	for k, _ := range unique {
		result.Data = append(result.Data, k)
	}

	ReturnJSON(w, 200, &result)
}

func (p *v1Provider) Series(w http.ResponseWriter, req *http.Request, projectID string) {
	queryParams := req.URL.Query()
	selectors := queryParams["match[]"]
	if selectors == nil {
		// behave like Prometheus, but do not proxy through
		ReturnError(w, errors.New("no match[] parameter provided"), 400)
		return
	}
	// enrich all match statements
	for i, sel := range selectors {
		newSel, err := util.AddLabelConstraintToSelector(sel, "project_id", projectID)
		if err != nil {
			ReturnError(w, err, 400)
			return
		}
		selectors[i] = newSel
	}

	resp, err := p.storage.Series(selectors, queryParams.Get("start"), queryParams.Get("end"))
	if err != nil {
		ReturnError(w, err, 503)
		return
	}

	ReturnResponse(w, resp)
}
