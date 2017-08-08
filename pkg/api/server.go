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

	"bytes"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/ui"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"io"
	"path/filepath"
)

var storageInstance storage.Driver
var keystoneInstance keystone.Driver

// Server initializes and starts the API server, hooking it up to the API router
func Server() error {

	prometheusAPIURL := viper.GetString("maia.prometheus_url")
	if prometheusAPIURL == "" {
		panic(fmt.Errorf("Prometheus endpoint not configured (maia.prometheus_url / MAIA_PROMETHEUS_URL)"))
	}

	mainRouter := setupRouter(keystone.NewKeystoneDriver(), storage.NewPrometheusDriver(prometheusAPIURL, map[string]string{}))

	http.Handle("/", mainRouter)

	//start HTTP server
	bindAddress := viper.GetString("maia.bind_address")
	util.LogInfo("listening on %s", bindAddress)

	// enable CORS
	c := cors.New(cors.Options{
		AllowedHeaders: []string{"X-Auth-Token"},
	})
	handler := c.Handler(mainRouter)

	return http.ListenAndServe(bindAddress, handler)
}

func setupRouter(keystone keystone.Driver, storage storage.Driver) *mux.Router {
	storageInstance = storage
	keystoneInstance = keystone

	mainRouter := mux.NewRouter()
	mainRouter.Methods(http.MethodGet).Path("/").HandlerFunc(redirectRootPage)

	// the API is versioned, other paths are not
	apiRouter := mainRouter.PathPrefix("/api/").Subrouter()
	mainRouter.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		allVersions := struct {
			Versions []VersionData `json:"versions"`
		}{[]VersionData{versionData()}}
		ReturnJSON(w, http.StatusMultipleChoices, allVersions)
	})
	//hook up the v1 API (this code is structured so that a newer API version can
	//be added easily later)
	v1Handler := NewV1Handler(keystone, storage)
	apiRouter.PathPrefix("/v1/").Handler(http.StripPrefix("/api/v1", v1Handler))

	// other endpoints
	// maia's federate endpoint
	mainRouter.Methods(http.MethodGet).Path("/federate").HandlerFunc(authorizedHandlerFunc(Federate, false, "metric:list"))
	// expression browser
	mainRouter.Methods(http.MethodGet).PathPrefix("/static/").HandlerFunc(serveStaticContent)
	mainRouter.Methods(http.MethodGet).PathPrefix("/graph").HandlerFunc(authorizedHandlerFunc(graph, true, "metric:show"))

	return mainRouter
}

func redirectRootPage(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/graph", http.StatusFound)
}

func serveStaticContent(w http.ResponseWriter, req *http.Request) {
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

// Federate handles GET /federate.
func Federate(w http.ResponseWriter, req *http.Request) {
	selectors, err := buildSelectors(req, keystoneInstance)
	if err != nil {
		util.LogInfo("Invalid request params %s", req.URL)
		ReturnError(w, err, 400)
		return
	}

	response, err := storageInstance.Federate(*selectors, req.Header.Get("Accept"))
	if err != nil {
		util.LogError("Could not get metrics for %s", selectors)
		ReturnError(w, err, 503)
		return
	}

	ReturnResponse(w, response)
}

func graph(w http.ResponseWriter, req *http.Request) {
	ui.ExecuteTemplate(w, req, "graph.html", keystoneInstance, nil)
}

/*
func forwardRequest(w http.ResponseWriter, req *http.Request) {
	resp, err := storageInstance.DelegateRequest(req)

	if err != nil {
		ReturnError(w, err, http.StatusBadGateway)
		return
	}

	ReturnResponse(w, resp)
}
*/
