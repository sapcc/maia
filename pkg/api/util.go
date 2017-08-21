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
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
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

const authTokenCookieName = "X-Auth-Token"
const authTokenHeader = "X-Auth-Token"
const authTokenExpiryHeader = "X-Auth-Token-Expiry"

var policyEnforcer *policy.Enforcer
var authErrorsCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "maia_logon_errors_count", Help: "Number of logon errors occured in Maia"})
var authFailuresCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "maia_logon_failures_count", Help: "Number of logon attempts failed due to wrong credentials"})

func init() {
	prometheus.MustRegister(authErrorsCounter, authFailuresCounter)
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
	payload, err := json.Marshal(&data)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		// TODO: @Arno, what is this good for?
		// payload := bytes.Replace(playload, []byte("\\u0026"), []byte("&"), -1)
		w.Write(payload)
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

//ReturnPromError produces a Prometheus error Response with HTTP Status code
func ReturnPromError(w http.ResponseWriter, err error, code int) {
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
	}

	jsonErr := storage.Response{Status: storage.StatusError, ErrorType: errorType, Error: err.Error()}
	ReturnJSON(w, code, jsonErr)
}

func scopeToLabelConstraint(req *http.Request, keystone keystone.Driver) (string, []string) {
	if projectID := req.Header.Get("X-Project-Id"); projectID != "" {
		children, err := keystone.ChildProjects(projectID)
		if err != nil {
			panic(err)
		}
		return "project_id", append([]string{projectID}, children...)
	} else if domainID := req.Header.Get("X-Domain-Id"); domainID != "" {
		return "domain_id", []string{domainID}
	}

	panic(fmt.Errorf("Missing OpenStack scope attributes in request header"))
}

// buildSelectors takes the selectors contained in the "match[]" URL query parameter(s)
// and extends them with a label-constrained for the project/domain scope
func buildSelectors(req *http.Request, keystone keystone.Driver) (*[]string, error) {
	labelKey, labelValues := scopeToLabelConstraint(req, keystone)

	queryParams := req.URL.Query()
	selectors := queryParams["match[]"]
	if selectors == nil {
		// behave like Prometheus, but do not proxy through
		return nil, errors.New("no match[] parameter provided")
	}
	// enrich all match statements
	for i, sel := range selectors {
		newSel, err := util.AddLabelConstraintToSelector(sel, labelKey, labelValues)
		if err != nil {
			return nil, err
		}
		selectors[i] = newSel
	}

	return &selectors, nil
}

func policyEngine() *policy.Enforcer {
	if policyEnforcer != nil {
		return policyEnforcer
	}

	// set up policy engine lazily
	bytes, err := ioutil.ReadFile(viper.GetString("keystone.policy_file"))
	if err != nil {
		panic(fmt.Errorf("Policy file %s not found: %s", viper.GetString("keystone.policy_file"), err))
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

func isPlainBasicAuth(req *http.Request) bool {
	if username, _, ok := req.BasicAuth(); ok {
		return !strings.ContainsAny(username, "@|")
	}
	return false
}

func authorizeRules(w http.ResponseWriter, req *http.Request, guessScope bool, rules []string) ([]string, keystone.AuthenticationError) {
	util.LogDebug("authenticate")
	matchedRules := []string{}

	domain, domainSet := mux.Vars(req)["domain"]

	// 1. check cookies or user-domain override via path prefix
	if cookie, err := req.Cookie(authTokenCookieName); err == nil && cookie.Value != "" && req.Header.Get(authTokenHeader) == "" {
		util.LogDebug("found cookie: %s", cookie.String())
		req.Header.Set(authTokenHeader, cookie.Value)
	} else if domainSet && isPlainBasicAuth(req) {
		util.LogDebug("setting user domain via URL: %s", domain)
		req.Header.Set("X-User-Domain-Name", domain)
	}

	// 2. authenticate
	context, err := keystoneInstance.AuthenticateRequest(req, guessScope)
	if err != nil {
		code := err.StatusCode()
		if code == keystone.StatusWrongCredentials {
			authFailuresCounter.Add(1)
			// expire the cookie and ask for new credentials if they are wrong
			username, _, ok := req.BasicAuth()
			if !ok {
				username = req.UserAgent()
			}
			util.LogInfo("Request with wrong credentials from %s: %s", username, err.Error())
			util.LogDebug("expire cookie and request username/password input")
			http.SetCookie(w, &http.Cookie{Name: authTokenCookieName, Path: "/", MaxAge: -1, Secure: false})
			w.Header().Set("WWW-Authenticate", "Basic")
		} else if code != keystone.StatusNoPermission && code == keystone.StatusMissingCredentials {
			// warn of possible technical issues
			util.LogWarning("Authentication error: %s", err.Error())
		} else {
			authErrorsCounter.Add(1)
		}
		return nil, err
	}

	// 3. authorize
	// make sure policyEnforcer is available
	pe := policyEngine()
	for _, rule := range rules {
		if pe.Enforce(rule, *context) {
			matchedRules = append(matchedRules, rule)
		}
	}

	if len(matchedRules) == 0 {
		return matchedRules, nil
	}

	return matchedRules, nil
}

func authorize(wrappedHandlerFunc func(w http.ResponseWriter, req *http.Request), guessScope bool, rule string) func(w http.ResponseWriter, req *http.Request) {

	return func(w http.ResponseWriter, req *http.Request) {
		matchedRules, err := authorizeRules(w, req, guessScope, []string{rule})
		if err != nil {
			if strings.HasPrefix(req.Header.Get("Accept"), storage.JSON) {
				ReturnPromError(w, err, err.StatusCode())
			} else {
				http.Error(w, err.Error(), err.StatusCode())
			}
		} else if len(matchedRules) > 0 {
			domain, domainSet := mux.Vars(req)["domain"]
			if domainSet && req.Header.Get("X-User-Domain-Name") != domain {
				// either the basic authentication credentials or the cookie do not match the domain in the URL
				if cookie, err := req.Cookie("X-Auth-Token"); err == nil && cookie.Value != "" {
					// there is a cookie: clear it and ask for new credentials
					http.SetCookie(w, &http.Cookie{Name: "X-Auth-Token", Path: "/", MaxAge: -1, Secure: false})
					w.Header().Set("WWW-Authenticate", "Basic")
					http.Error(w, fmt.Sprintf("User domain changed from %s to %s. Please log on again.", req.Header.Get("X-User-Domain-Name"), domain), http.StatusUnauthorized)
				} else {
					// redirect to the domain that fits the user credentials
					http.Redirect(w, req, strings.Replace(req.URL.Path, domain, req.Header.Get("X-User-Domain-Name"), 1), http.StatusFound)
				}
			}
			// set cookie
			util.LogDebug("Setting cookie: %s", req.Header.Get(authTokenHeader))
			expiryStr := req.Header.Get(authTokenExpiryHeader)
			expiry, err := time.Parse(time.RFC3339Nano, expiryStr)
			if err != nil {
				util.LogWarning("Incompatible token format for expiry data: %s", expiryStr)
				expiry = time.Now().UTC().Add(viper.GetDuration("keystone.token_cache_time"))
			}
			http.SetCookie(w, &http.Cookie{Name: authTokenCookieName, Path: "/", Value: req.Header.Get(authTokenHeader),
				Expires: expiry.UTC(), Secure: false})
			wrappedHandlerFunc(w, req)
		} else {
			// authenticated but not authorized
			h := req.Header
			username := h.Get("X-User-Name")
			userDomain := h.Get("X-User-Domain-Name")
			scopedDomain := h.Get("X-Domain-Name")
			scopedProject := h.Get("X-Project-Name")
			scopedProjectDomain := h.Get("X-Project-Domain-Name")
			scope := scopedProject + " in domain " + scopedProjectDomain
			if scopedProject == "" {
				scope = scopedDomain
			}
			actRoles := h.Get("X-Roles")
			reqRoles := viper.GetString("keystone.roles")
			http.Error(w, fmt.Sprintf("User %s@%s does not have monitoring permissions on %s (actual roles: %s, required roles: %s)", username, userDomain, scope, actRoles, reqRoles), http.StatusForbidden)
		}
	}
}

func gaugeInflight(handler http.Handler) http.Handler {
	inflightGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "maia_requests_inflight", Help: "Number of inflight HTTP requests served by Maia"})
	prometheus.MustRegister(inflightGauge)

	return promhttp.InstrumentHandlerInFlight(inflightGauge, handler)
}

func observeDuration(handlerFunc http.HandlerFunc, apiOperation string) http.HandlerFunc {
	durationHistogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "maia_request_duration_seconds", Help: "Duration/latency of a Maia request", Buckets: prometheus.DefBuckets, ConstLabels: prometheus.Labels{"operation": apiOperation}}, nil)
	prometheus.MustRegister(durationHistogram)

	return promhttp.InstrumentHandlerDuration(durationHistogram, handlerFunc)
}

func observeResponseSize(handlerFunc http.HandlerFunc, apiOperation string) http.HandlerFunc {
	durationHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "maia_response_size_bytes", Help: "Size of the Maia response (e.g. to a query)", Buckets: prometheus.DefBuckets, ConstLabels: prometheus.Labels{"operation": apiOperation}}, nil)
	prometheus.MustRegister(durationHistogram)

	return promhttp.InstrumentHandlerResponseSize(durationHistogram, http.HandlerFunc(handlerFunc)).ServeHTTP
}
