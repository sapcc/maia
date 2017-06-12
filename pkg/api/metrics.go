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

	"github.com/sapcc/maia/pkg/cmd/auth"
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
	}

	ReturnResponse(w, 200, response)
}
