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

	"errors"
	"github.com/gorilla/mux"
	"github.com/sapcc/maia/pkg/maia"
	"github.com/sapcc/maia/pkg/util"
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

func (p *v1Provider) LabelValues(w http.ResponseWriter, req *http.Request, projectID string) {
	// TODO: use series and filter accordingly
	resp, err := p.storage.LabelValues(mux.Vars(req)["name"])
	if err != nil {
		ReturnError(w, err, 503)
		return
	}

	ReturnResponse(w, resp)
}

func (p *v1Provider) Series(w http.ResponseWriter, req *http.Request, projectID string) {
	queryParams := req.URL.Query()
	selectors := queryParams["match[]"]
	if selectors == nil {
		// behave like Prometheus, but do not proxy through
		ReturnError(w, errors.New("no match[] parameter provided"), 400)
		return
	}

	newSelectors := make([]string, len(selectors))
	for i, sel := range queryParams["match[]"] {
		newSel, perr := util.AddLabelConstraintToSelector(sel, "project_id", projectID)
		newSelectors[i] = newSel
		if perr != nil {
			ReturnError(w, perr, 400)
			return
		}
	}

	resp, err := p.storage.Series(newSelectors, queryParams.Get("start"), queryParams.Get("end"))
	if err != nil {
		ReturnError(w, err, 503)
		return
	}

	ReturnResponse(w, resp)
}
