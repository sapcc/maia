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

	"fmt"
	dto "github.com/prometheus/client_model/go"
	"io"
)

// RFC822 timestamp format
const RFC822 = "Mon, 2 Jan 2006 15:04:05 GMT"

var prometheusCoreHeaders = make(map[string]string)

//versionData is used by version advertisement handlers.
type versionData struct {
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

	// TODO: what is /metrics? It is not a Prometheus API
	r.Methods("GET").Path("/v1/metrics").HandlerFunc(AuthorizedHandlerFunc(p.ListMetrics, p.keystone, "metrics:list"))

	r.Methods("GET").Path("/v1/query").HandlerFunc(AuthorizedHandlerFunc(p.Query, p.keystone, "metrics:query"))
	r.Methods("GET").Path("/v1/query_range").HandlerFunc(AuthorizedHandlerFunc(p.QueryRange, p.keystone, "metrics:query"))

	r.Methods("GET").Path("/v1/label/:name/values").HandlerFunc(AuthorizedHandlerFunc(p.LabelValues, p.keystone, "metrics:list"))

	r.Methods("GET").Path("/v1/series").HandlerFunc(AuthorizedHandlerFunc(p.ListSeries, p.keystone, "metrics:list"))

	return r, p.versionData
}

//ReturnMetrics returns metrics in the prometheus text format
func ReturnMetrics(w http.ResponseWriter, format expfmt.Format, code int, data *dto.MetricFamily) {
	//headers
	time := time.Now().UTC().Format(RFC822)
	w.Header().Set("Date", time)
	initCoreHeaders()
	for k, v := range prometheusCoreHeaders {
		w.Header().Set(k, v)
	}
	// body
	enc := expfmt.NewEncoder(w, format)
	enc.Encode(data)
}

//ReturnResponse basically forwards a received response.
//Returns 404 if no metrics where found
func ReturnResponse(w http.ResponseWriter, code int, response *http.Response) {

	for k, v := range response.Header {
		w.Header().Set(k, strings.Join(v, ";"))
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	body := buf.String()
	// request to prometheus was successful, but nothing was found
	if (w.Header().Get("Content-Length") == string(0)) || (len(body) == 0) {
		fmt.Println("---->", w.Header().Get("Content-Length"))
		code = 404
	}
	w.WriteHeader(code)

	io.WriteString(w, body)

}

//ReturnJSON is a convenience function for HTTP handlers returning JSON data.
//The `code` argument specifies the HTTP response code, usually 200.
func ReturnJSON(w http.ResponseWriter, code int, data interface{}) {
	escapedJSON, err := json.MarshalIndent(&data, "", "  ")
	jsonData := bytes.Replace(escapedJSON, []byte("\\u0026"), []byte("&"), -1)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		w.Write(jsonData)
	} else {
		http.Error(w, err.Error(), 500)
	}
}

//ReturnError produces an error response with HTTP status code if the given
//error is non-nil. Otherwise, nothing is done and false is returned.
func ReturnError(w http.ResponseWriter, err error, code int) bool {
	if err == nil {
		return false
	}

	http.Error(w, err.Error(), code)
	return true
}

//RequireJSON will parse the request body into the given data structure, or
//write an error response if that fails.
func RequireJSON(w http.ResponseWriter, r *http.Request, data interface{}) bool {
	err := json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		http.Error(w, "request body is not valid JSON: "+err.Error(), 400)
		return false
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
