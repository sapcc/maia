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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/databus23/goslo.policy"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

// utility functionality

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

// provides version data
func versionData() VersionData {
	return VersionData{
		Status: "CURRENT",
		ID:     "v1",
		Links: []versionLinkData{
			{
				Relation: "self",
				URL:      keystoneInstance.ServiceURL(),
			},
			{
				Relation: "describedby",
				URL:      "https://github.com/sapcc/maia/tree/master/README.md",
				Type:     "text/html",
			},
		},
	}
}

//ReturnResponse basically forwards a received Response.
func ReturnResponse(w http.ResponseWriter, response *http.Response) {
	defer response.Body.Close()

	// copy headers
	for k, v := range response.Header {
		w.Header().Set(k, strings.Join(v, ";"))
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	body := buf.String()
	w.WriteHeader(response.StatusCode)

	io.WriteString(w, body)
}

//ReturnJSON is a convenience function for HTTP handlers returning JSON data.
//The `code` argument specifies the HTTP Response code, usually 200.
func ReturnJSON(w http.ResponseWriter, code int, data interface{}) {
	escapedJSON, err := json.Marshal(&data)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		// TODO: @Arno, what is this good for?
		jsonData := bytes.Replace(escapedJSON, []byte("\\u0026"), []byte("&"), -1)
		w.Write(jsonData)
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

//ReturnError produces a Prometheus error Response with HTTP Status code if the given
//error is non-nil. Otherwise, nothing is done and false is returned.
func ReturnError(w http.ResponseWriter, err error, code int) bool {
	if err == nil {
		return false
	}

	var errorType = storage.ErrorNone
	switch code {
	case http.StatusBadRequest:
		errorType = storage.ErrorBadData
	case http.StatusUnprocessableEntity:
		errorType = storage.ErrorExec
	case http.StatusInternalServerError:
		errorType = storage.ErrorInternal
	case http.StatusServiceUnavailable:
		errorType = storage.ErrorTimeout
	default:
		http.Error(w, err.Error(), code)
		return true
	}

	jsonErr := storage.Response{Status: storage.StatusError, ErrorType: errorType, Error: err.Error()}
	ReturnJSON(w, code, jsonErr)

	return true
}

func scopeToLabelConstraint(req *http.Request, keystone keystone.Driver) (string, string) {
	if projectID := req.Header.Get("X-Project-Id"); projectID != "" {
		children := keystone.ChildProjects(projectID)
		for _, subID := range children {
			projectID = projectID + "|" + subID
		}
		return "project_id", projectID
	} else if domainID := req.Header.Get("X-Domain-Id"); domainID != "" {
		return "domain_id", domainID
	}

	panic(fmt.Errorf("Missing OpenStack scope attributes in request header"))
}

// buildSelectors takes the selectors contained in the "match[]" URL query parameter(s)
// and extends them with a label-constrained for the project/domain scope
func buildSelectors(req *http.Request, keystone keystone.Driver) (*[]string, error) {
	labelKey, labelValue := scopeToLabelConstraint(req, keystone)

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

func authorizedHandlerFunc(wrappedHandlerFunc func(w http.ResponseWriter, req *http.Request), rule string) func(w http.ResponseWriter, req *http.Request) {

	return func(w http.ResponseWriter, req *http.Request) {
		util.LogDebug("authenticate")

		// 1. authenticate
		context, err := keystoneInstance.AuthenticateRequest(req)
		if err != nil {
			util.LogInfo(err.Error())
			w.Header().Set("WWW-Authenticate", "Basic")
			ReturnError(w, err, http.StatusUnauthorized)
			return
		}

		// 2. authorize
		// make sure policyEnforcer is available
		pe := policyEngine()
		if !pe.Enforce(rule, *context) {
			err := fmt.Errorf("User %s with roles %s does not fulfill authorization rule %s", context.Request["user_id"], context.Roles, rule)
			util.LogInfo(err.Error())
			ReturnError(w, err, http.StatusForbidden)
			return
		}

		// call
		wrappedHandlerFunc(w, req)

		http.SetCookie(w, &http.Cookie{Name: "X-Auth-Token", Value: req.Header.Get("X-Auth-Token"), Secure: true})
	}
}
