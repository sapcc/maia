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

	"github.com/pkg/errors"
	"github.com/sapcc/maia/pkg/maia"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"fmt"
)

// MetricList is the model for JSON returned by the ListMetrics API call
type MetricList struct {
	NextURL string         `json:"next,omitempty"`
	PrevURL string         `json:"previous,omitempty"`
	Metrics []*maia.Metric `json:"metrics"`
}

//ListMetrics handles GET /v1/metrics.
func (p *v1Provider) ListMetrics(w http.ResponseWriter, req *http.Request) {
	util.LogDebug("api.ListMetrics")

	auth := p.CheckBasicAuth(req)
	if auth.err != nil {
		util.LogError(auth.err.Error())
		ReturnError(w,auth.err,404)
		return
	}

	tenantId := ""
	if auth != nil {
		if auth.ProjectId != "" {
			tenantId = auth.ProjectId
		} else if auth.DomainId != "" {
			tenantId = auth.DomainId
		} else {
			util.LogError("No project_id or domain_id found. Aborting.")
			ReturnError(w,auth.err,404)
			return
		}
	}

	util.LogDebug("Getting metrics for project/domain: %s .", tenantId)

	fmt.Println("--",viper.IsSet("keystone"))

	// if [keystone] section in config
	if viper.IsSet("keystone") {
		util.LogDebug("Using keystone backend.")
		token := p.GetTokenFromBasicAuth(auth)

		//TODO: caching and check token
		//token := p.CheckToken(req)

		if !token.Require(w, "metric:list") {
			return
		}
	}

	response, err := p.storage.ListMetrics(auth.ProjectId)
	if err != nil {
		util.LogError("Could not get metrics for project %s", auth.ProjectId)
	}

	ReturnResponse(w, 200, response)
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
