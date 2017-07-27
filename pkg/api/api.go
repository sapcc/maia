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
	"fmt"
	"github.com/gorilla/mux"
	"github.com/prometheus/common/model"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"io/ioutil"
	"sort"
	"time"
)

func scopeToLabelConstraint(req *http.Request) (string, string) {
	if projectID := req.Header.Get("X-Project-Id"); projectID != "" {
		return "project_id", projectID
	} else if domainID := req.Header.Get("X-Domain-Id"); domainID != "" {
		return "domain_id", domainID
	}

	panic(fmt.Errorf("Missing OpenStack scope attributes in request header"))
}

// Federate handles GET /federate.
func (p *v1Provider) Federate(w http.ResponseWriter, req *http.Request) {
	selectors, err := buildSelectors(req)
	if err != nil {
		util.LogInfo("Invalid request params %s", req.URL)
		ReturnError(w, err, 400)
		return
	}

	response, err := p.storage.Federate(*selectors, req.Header.Get("Accept"))
	if err != nil {
		util.LogError("Could not get metrics for %s", selectors)
		ReturnError(w, err, 503)
		return
	}

	ReturnResponse(w, response)
}

func (p *v1Provider) Query(w http.ResponseWriter, req *http.Request) {
	labelKey, labelValue := scopeToLabelConstraint(req)

	queryParams := req.URL.Query()
	newQuery, err := util.AddLabelConstraintToExpression(queryParams.Get("query"), labelKey, labelValue)
	if err != nil {
		ReturnError(w, err, 400)
		return
	}

	resp, err := p.storage.Query(newQuery, queryParams.Get("time"), queryParams.Get("timeout"), req.Header.Get("Accept"))
	if err != nil {
		ReturnError(w, err, 503)
		return
	}

	ReturnResponse(w, resp)
}

func (p *v1Provider) QueryRange(w http.ResponseWriter, req *http.Request) {
	labelKey, labelValue := scopeToLabelConstraint(req)

	queryParams := req.URL.Query()
	newQuery, err := util.AddLabelConstraintToExpression(queryParams.Get("query"), labelKey, labelValue)
	if err != nil {
		ReturnError(w, err, 400)
		return
	}

	resp, err := p.storage.QueryRange(newQuery, queryParams.Get("start"), queryParams.Get("end"), queryParams.Get("step"), queryParams.Get("timeout"), req.Header.Get("Accept"))
	if err != nil {
		ReturnError(w, err, 503)
		return
	}

	ReturnResponse(w, resp)
}

// LabelValues utilizes the series API in order to implement a tenant-aware list.
// This is a complex operation.
func (p *v1Provider) LabelValues(w http.ResponseWriter, req *http.Request) {
	labelKey, labelValue := scopeToLabelConstraint(req)

	name := model.LabelName(mux.Vars(req)["name"])
	// do not list label values from series older than maia.label_value_ttl
	ttl, err := time.ParseDuration(viper.GetString("maia.label_value_ttl"))
	if err != nil {
		ReturnError(w, errors.New("Invalid Maia configuration (maia.label_value_ttl)"), 500)
		return
	}

	start := time.Now().Add(-ttl)
	end := time.Now()
	resp, err := p.storage.Series([]string{"{" + labelKey + "=\"" + labelValue + "\"," + string(name) + "!=\"\"}"}, start.Format(time.RFC3339), end.Format(time.RFC3339), req.Header.Get("Accept"))
	if err != nil {
		ReturnError(w, err, 502)
		return
	}

	// extract label values from series
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ReturnError(w, err, resp.StatusCode)
		return
	}

	var sr storage.SeriesResponse
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
	var result storage.LabelValuesResponse
	result.Status = sr.Status
	result.Data = model.LabelValues{}
	for k := range unique {
		result.Data = append(result.Data, k)
	}
	sort.Sort(result.Data)

	ReturnJSON(w, 200, &result)
}

// buildSelectors takes the selectors contained in the "match[]" URL query parameter(s)
// and extends them with a label-constrained for the project/domain scope
func buildSelectors(req *http.Request) (*[]string, error) {
	labelKey, labelValue := scopeToLabelConstraint(req)

	queryParams := req.URL.Query()
	selectors := queryParams["match[]"]
	if selectors == nil {
		// behave like Prometheus, but do not proxy through
		return nil, errors.New("no match[] parameter provided")
	}
	// enrich all match statements
	for i, sel := range selectors {
		newSel, err := util.AddLabelConstraintToSelector(sel, labelKey, labelValue)
		if err != nil {
			return nil, err
		}
		selectors[i] = newSel
	}

	return &selectors, nil
}

func (p *v1Provider) Series(w http.ResponseWriter, req *http.Request) {
	selectors, err := buildSelectors(req)
	if err != nil {
		ReturnError(w, err, 400)
		return
	}
	queryParams := req.URL.Query()
	resp, err := p.storage.Series(*selectors, queryParams.Get("start"), queryParams.Get("end"), req.Header.Get("Accept"))
	if err != nil {
		ReturnError(w, err, 502)
		return
	}

	ReturnResponse(w, resp)
}
