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

	"fmt"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sapcc/maia/pkg/maia"
	"github.com/sapcc/maia/pkg/util"
	"strconv"
)

// EventList is the model for JSON returned by the ListEvents API call
type MetricList struct {
	NextURL string              `json:"next,omitempty"`
	PrevURL string              `json:"previous,omitempty"`
	Metrics  []*maia.ListMetrics `json:"metrics"`
	Total   int                 `json:"total"`
}

//ListEvents handles GET /v1/events.
func (p *v1Provider) ListEvents(res http.ResponseWriter, req *http.Request) {
	util.LogDebug("* api.ListEvents: Check token")
	token := p.CheckToken(req)
	if !token.Require(res, "event:list") {
		return
	}

	util.LogDebug("api.ListMetrics: Create filter")

	util.LogDebug("api.ListMetrics: call maia.GetMetric()")
	tenantId, err := getTenantId(req, res)
	if err != nil {
		return
	}
	metrics, err := maia.GetMetrics(tenantId, p.keystone, p.storage)
	if ReturnError(res, err) {
		util.LogError("api.ListEvents: error %s", err)
		return
	}

	metricList := MetricList{Metrics: metrics}

	ReturnJSON(res, 200, metricList)
}

//GetEvent handles GET /v1/metrics/projects/:project_id.
func (p *v1Provider) GetEventDetails(res http.ResponseWriter, req *http.Request) {
	token := p.CheckToken(req)
	if !token.Require(res, "metric:show") {
		return
	}

	tenantId, err := getTenantId(req, res)
	if err != nil {
		return
	}

	metric, err := maia.GetMetrics(tenantId, p.keystone, p.storage)

	if ReturnError(res, err) {
		return
	}
	if metric == nil {
		err := fmt.Errorf("No metrics found for project %s", tenantId)
		http.Error(res, err.Error(), 404)
		return
	}
	ReturnJSON(res, 200, metric)
}

func getTenantId(r *http.Request, w http.ResponseWriter) (string, error) {
	projectId := r.FormValue("project_id")
	domainId := r.FormValue("domain_id")
	var tenantId string
	if projectId != "" {
		tenantId = projectId
	}
	if domainId != "" {
		if projectId != "" {
			err := errors.New("domain_id and project_id cannot both be specified")
			http.Error(w, err.Error(), 400)
			return "", err
		}
		tenantId = domainId
	}
	return tenantId, nil
}