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

	"github.com/gorilla/mux"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/util"
)

// Set up and start the API server, hooking it up to the API router
func Server(keystone keystone.Driver, storage storage.Driver, bind_address string) error {

	mainRouter := mux.NewRouter()

	//hook up the v1 API (this code is structured so that a newer API version can
	//be added easily later)
	v1Router, v1VersionData := NewV1Router(keystone, storage)
	// TODO: where is the /api prefix?
	mainRouter.PathPrefix("/api/v1/").Handler(v1Router)

	//add the version advertisement that lists all available API versions
	mainRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		allVersions := struct {
			Versions []versionData `json:"versions"`
		}{[]versionData{v1VersionData}}
		ReturnJSON(w, 300, allVersions)
	})

	http.Handle("/", mainRouter)

	//start HTTP server
	util.LogInfo("listening on %s", bind_address)
	return http.ListenAndServe(bind_address, nil)
}
