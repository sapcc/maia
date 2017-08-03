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
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/ui"

	"bytes"
	"fmt"
	"github.com/databus23/goslo.policy"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"io"
	"io/ioutil"
	"path/filepath"
)

//VersionData is used by version advertisement handlers.
type VersionData struct {
	Status string            `json:"status"`
	ID     string            `json:"id"`
	Links  []versionLinkData `json:"links"`
}

//versionLinkData is used by version advertisement handlers, as part of the
//VersionData struct.
type versionLinkData struct {
	URL      string `json:"href"`
	Relation string `json:"rel"`
	Type     string `json:"type,omitempty"`
}

// class for Prometheus v1 API provider implementation
type v1Provider struct {
	keystone    keystone.Driver
	storage     storage.Driver
	versionData VersionData
}

var policyEnforcer *policy.Enforcer

func policyEngine() *policy.Enforcer {
	if policyEnforcer != nil {
		return policyEnforcer
	}

	// set up policy engine lazily
	bytes, err := ioutil.ReadFile(viper.GetString("maia.policy_file"))
	if err != nil {
		panic(fmt.Errorf("Policy file %s not found: %s", viper.GetString("maia.policy_file"), err))
	}
	var rules map[string]string
	err = json.Unmarshal(bytes, &rules)
	if err != nil {
		panic(err)
	}
	policyEnforcer, err = policy.NewEnforcer(rules)
	if err != nil {
		panic(err)
	}

	return policyEnforcer
}

//NewV1Router creates a http.Handler that serves the Maia v1 API.
//It also returns the VersionData for this API version which is needed for the
//version advertisement on "GET /".
func NewV1Router(keystone keystone.Driver, storage storage.Driver) (http.Handler, VersionData) {

	r := mux.NewRouter()
	p := &v1Provider{
		keystone: keystone,
		storage:  storage,
	}
	p.versionData = VersionData{
		Status: "CURRENT",
		ID:     "v1",
		Links: []versionLinkData{
			{
				Relation: "self",
				URL:      p.Path(),
			},
			{
				Relation: "describedby",
				URL:      "https://github.com/sapcc/maia/tree/master/docs",
				Type:     "text/html",
			},
		},
	}

	// version info
	r.Methods("GET").Path("/api/v1/").HandlerFunc(func(res http.ResponseWriter, _ *http.Request) {
		ReturnJSON(res, 200, map[string]interface{}{"version": p.versionData})
	})

	// maia's own metrics
	r.Methods("GET").Path("/federate").HandlerFunc(p.AuthorizedHandlerFunc(p.Federate, "metric:list"))
	// tenant-aware query
	r.Methods("GET").Path("/api/v1/query").HandlerFunc(p.AuthorizedHandlerFunc(p.Query, "metric:show"))
	r.Methods("GET").Path("/api/v1/query_range").HandlerFunc(p.AuthorizedHandlerFunc(p.QueryRange, "metric:show"))
	// tenant-aware label value lists
	r.Methods("GET").Path("/api/v1/label/{name}/values").HandlerFunc(p.AuthorizedHandlerFunc(p.LabelValues, "metric:list"))
	// tenant-aware series metadata
	r.Methods("GET").Path("/api/v1/series").HandlerFunc(p.AuthorizedHandlerFunc(p.Series, "metric:list"))

	// forward requests for static content
	r.Methods(http.MethodGet).PathPrefix("/static/").HandlerFunc(p.serveStaticContent)
	r.Methods("GET").PathPrefix("/graph").HandlerFunc(p.AuthorizedHandlerFunc(p.graph, "metric:show"))

	return r, p.versionData
}

func (p *v1Provider) serveStaticContent(w http.ResponseWriter, req *http.Request) {
	fp := req.URL.Path
	fp = filepath.Join("web", fp)

	info, err := ui.AssetInfo(fp)
	if err != nil {
		util.LogWarning("Could not get file info: %v", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	file, err := ui.Asset(fp)
	if err != nil {
		if err != io.EOF {
			util.LogWarning("Could not get file info: %v", err)
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}

	http.ServeContent(w, req, info.Name(), info.ModTime(), bytes.NewReader(file))
}

func (p *v1Provider) graph(w http.ResponseWriter, req *http.Request) {
	ui.ExecuteTemplate(w, req, "graph.html", nil)
}

func (p *v1Provider) AuthorizedHandlerFunc(wrappedHandlerFunc func(w http.ResponseWriter, req *http.Request), rule string) func(w http.ResponseWriter, req *http.Request) {

	return func(w http.ResponseWriter, req *http.Request) {
		util.LogDebug("authenticate")

		// 1. authenticate
		context, err := p.keystone.AuthenticateRequest(req)
		if err != nil {
			util.LogInfo(err.Error())
			w.Header().Set("WWW-Authenticate", "Basic")
			ReturnError(w, err, 401)
			return
		}

		// 2. authorize
		// make sure policyEnforcer is available
		pe := policyEngine()
		if !pe.Enforce(rule, *context) {
			err := fmt.Errorf("User %s with roles %s does not fulfill authorization rule %s", context.Request["user_id"], context.Roles, rule)
			util.LogInfo(err.Error())
			ReturnError(w, err, 403)
			return
		}

		// call
		wrappedHandlerFunc(w, req)

		http.SetCookie(w, &http.Cookie{Name: "X-Auth-Token", Value: req.Header.Get("X-Auth-Token")})
	}
}

//Path constructs a full URL for a given URL path below the /v1/ endpoint.
func (p *v1Provider) Path(elements ...string) string {
	parts := []string{
		strings.TrimSuffix( /*p.Driver.Cluster().Config.CatalogURL*/ "", "/"),
		"v1",
	}
	parts = append(parts, elements...)
	return strings.Join(parts, "/")
}
