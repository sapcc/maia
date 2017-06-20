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
	"github.com/prometheus/common/expfmt"
	"github.com/sapcc/maia/pkg/auth"
	"github.com/sapcc/maia/pkg/storage"

	"bytes"
	dto "github.com/prometheus/client_model/go"
	"io"
	"time"
)

// RFC822 timestamp format
const RFC822 = "Mon, 2 Jan 2006 15:04:05 GMT"

var prometheusCoreHeaders = make(map[string]string)

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

// Prometheus status strings
type status string

const (
	statusSuccess status = "success"
	statusError          = "error"
)

// Prometheus error types
type errorType string

const (
	errorNone     errorType = ""
	errorTimeout            = "timeout"
	errorCanceled           = "canceled"
	errorExec               = "execution"
	errorBadData            = "bad_data"
	errorInternal           = "internal"
)

// Prometheus response object (JSON)
type response struct {
	Status    status      `json:"status"`
	Data      interface{} `json:"data,omitempty"`
	ErrorType errorType   `json:"errorType,omitempty"`
	Error     string      `json:"error,omitempty"`
}

func initCoreHeaders() {
	prometheusCoreHeaders["User-Agent"] = "Prometheus/"
	prometheusCoreHeaders["Accept"] = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.7,text/plain;version=0.0.4;q=0.3,*/*;q=0.1"
	prometheusCoreHeaders["Accept-Encoding"] = "gzip"
	prometheusCoreHeaders["Connection"] = "close"
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

	r.Methods("GET").Path("/api/v1/").HandlerFunc(func(res http.ResponseWriter, _ *http.Request) {
		ReturnJSON(res, 200, map[string]interface{}{"version": p.versionData})
	})

	// maia's own metrics
	r.Methods("GET").Path("/metrics").HandlerFunc(AuthorizedHandlerFunc(p.ListMetrics, p.keystone, "metric:list"))
	// tenant-aware query
	r.Methods("GET").Path("/api/v1/query").HandlerFunc(AuthorizedHandlerFunc(p.Query, p.keystone, "metric:show"))
	r.Methods("GET").Path("/api/v1/query_range").HandlerFunc(AuthorizedHandlerFunc(p.QueryRange, p.keystone, "metric:show"))
	// tenant-aware label value lists
	r.Methods("GET").Path("/api/v1/label/{name}/values").HandlerFunc(AuthorizedHandlerFunc(p.LabelValues, p.keystone, "metric:list"))
	// tenant-aware series metadata
	r.Methods("GET").Path("/api/v1/series").HandlerFunc(AuthorizedHandlerFunc(p.Series, p.keystone, "metric:list"))

	return r, p.versionData
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

// TODO what is this?
//Path constructs a full URL for a given URL path below the /v1/ endpoint.
func (p *v1Provider) Path(elements ...string) string {
	parts := []string{
		strings.TrimSuffix( /*p.Driver.Cluster().Config.CatalogURL*/ "", "/"),
		"v1",
	}
	parts = append(parts, elements...)
	return strings.Join(parts, "/")
}
