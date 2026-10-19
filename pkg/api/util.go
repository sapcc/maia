// SPDX-FileCopyrightText: 2017 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	policy "github.com/databus23/goslo.policy"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"

	"github.com/sapcc/go-bits/logg"

	"github.com/SAP-cloud-infrastructure/maia/pkg/keystone"
	"github.com/SAP-cloud-infrastructure/maia/pkg/storage"
	"github.com/SAP-cloud-infrastructure/maia/pkg/util"
)

// utility functionality

// contextKey is a custom type to prevent collisions with other packages
// that might use string keys in context.Context. This is a Go best practice
// that ensures our keystone selection context keys remain isolated.
type contextKey string

const (
	keystoneTypeKey     contextKey = "maia.keystone.type"
	keystoneInstanceKey contextKey = "maia.keystone.instance"
)

// VersionData is used by version advertisement handlers.
type VersionData struct {
	Status string            `json:"status"`
	ID     string            `json:"id"`
	Links  []versionLinkData `json:"links"`
}

// versionLinkData is used by version advertisement handlers, as part of the
// VersionData struct.
type versionLinkData struct {
	URL      string `json:"href"`
	Relation string `json:"rel"`
	Type     string `json:"type,omitempty"`
}

const authTokenCookieName = "X-Auth-Token" //nolint:gosec //not a credential
const userDomainCookieName = "X-User-Domain-Name"
const authTokenHeader = "X-Auth-Token" //nolint:gosec //not a credential
const userDomainHeader = "X-User-Domain-Name"
const authTokenExpiryHeader = "X-Auth-Token-Expiry" //nolint:gosec //not a credential

var policyEnforcer *policy.Enforcer
var authErrorsCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "maia_logon_errors_count", Help: "Number of logon errors occurred in Maia"})
var authFailuresCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "maia_logon_failures_count", Help: "Number of logon attempts failed due to wrong credentials"})
var promErrorsCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "maia_tsdb_errors_count", Help: "Number of technical errors occurred when accessing Maia's underlying TSDB (i.e. Prometheus)"})
var requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "maia_requests_total", Help: "Total number of HTTP requests handled by Maia, by handler, HTTP method and response code"},
	[]string{"handler", "code", "method"})

func init() {
	prometheus.MustRegister(authErrorsCounter, authFailuresCounter, promErrorsCounter, requestsTotal)
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
				URL:      "https://github.com/SAP-cloud-infrastructure/maia/tree/master/README.md",
				Type:     "text/html",
			},
		},
	}
}

// ReturnResponse basically forwards a received Response.
func ReturnResponse(w http.ResponseWriter, response *http.Response) {
	defer response.Body.Close()

	// copy headers
	for k, v := range response.Header {
		w.Header().Set(k, strings.Join(v, ";"))
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body) //nolint:errcheck // TODO go-bits replacement?

	body := buf.String()
	w.WriteHeader(response.StatusCode)

	io.WriteString(w, body) //nolint:errcheck // TODO go-bits? otherwise I can make return response return an err
}

// ReturnJSON is a convenience function for HTTP handlers returning JSON data.
// The `code` argument specifies the HTTP Response code, usually 200.
func ReturnJSON(w http.ResponseWriter, code int, data any) {
	payload, err := json.Marshal(&data)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		// restore "&" in links that are broken by the json.Marshaller
		payload = bytes.ReplaceAll(payload, []byte("\\u0026"), []byte("&"))
		_, err = w.Write(payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// ReturnPromError produces a Prometheus error Response with HTTP Status code
func ReturnPromError(w http.ResponseWriter, err error, code int) {
	if code >= 500 {
		promErrorsCounter.Add(1)
	}

	var errorType storage.ErrorType
	switch code {
	case http.StatusBadRequest:
		errorType = storage.ErrorBadData
	case http.StatusUnprocessableEntity:
		errorType = storage.ErrorExec
	case http.StatusServiceUnavailable:
		errorType = storage.ErrorTimeout
	default:
		errorType = storage.ErrorInternal
	}

	jsonErr := storage.Response{Status: storage.StatusError, ErrorType: errorType, Error: err.Error()}
	ReturnJSON(w, code, jsonErr)
}

// scopeToLabelConstraint derives the Prometheus tenant filter (label key + values)
// for a request, in this precedence order:
//
//  1. X-Project-Id header  → project_id filter (+ child projects)
//  2. X-Domain-Id header   → domain_id filter
//  3. project_id query param → project_id filter (+ child projects)
//
// The two header branches are trusted WITHOUT a membership check because
// keystone.AuthenticateRequest strips any inbound copies and re-sets them from
// the validated token — they cannot carry client input. The query-param branch
// (used by the React UI) IS client-controlled, so it must membership-check the
// requested project against the user's monitoring-scoped projects before use.
// If that invariant in AuthenticateRequest is ever removed, branches 1/2 become
// spoofable. The invariant is guarded across both files by a test pair:
// keystone.TestAuthenticateRequest (proves inbound scope headers are stripped
// and re-set from the token) and TestScopeHeaderWinsUnchecked (proves the
// header branch here resolves unchecked and outranks the query param).
//
//nolint:gocritic // ifElseChain: sequential header/param precedence reads clearer than a switch here
func scopeToLabelConstraint(req *http.Request, keystoneDriver keystone.Driver) (string, []string) {
	ctx := req.Context()
	logg.Debug("[SCOPE_DEBUG] Starting scope resolution")

	if projectID := req.Header.Get("X-Project-Id"); projectID != "" {
		logg.Debug("[SCOPE_DEBUG] Found X-Project-Id: %s", projectID)
		children, err := keystoneDriver.ChildProjects(ctx, projectID)
		if err != nil {
			logg.Error("[SCOPE_DEBUG] ChildProjects failed for %s: %v", projectID, err)
			panic(err)
		}
		logg.Debug("[SCOPE_DEBUG] ChildProjects for %s returned: %v", projectID, children)
		allProjects := append([]string{projectID}, children...)
		logg.Debug("[SCOPE_DEBUG] Final project list: %v", allProjects)
		return "project_id", appendSentinelValue(allProjects)
	} else if domainID := req.Header.Get("X-Domain-Id"); domainID != "" {
		logg.Debug("[SCOPE_DEBUG] Found X-Domain-Id: %s", domainID)
		return "domain_id", appendSentinelValue([]string{domainID})
	}

	// MAIA: fallback — React UI passes project_id as a query param (injected by useAPIQuery).
	// Read it here so that scope-aware queries work without requiring explicit scope headers.
	// SECURITY: unlike the X-Project-Id header (set server-side from the validated token),
	// this value is client-controlled. Verify the authenticated user actually has a
	// monitoring role on the requested project before trusting it, otherwise any
	// authenticated user could read another tenant's metrics by supplying a foreign
	// project_id. X-User-Id is set from the validated token in AuthenticateRequest.
	if projectID := req.URL.Query().Get("project_id"); projectID != "" {
		logg.Debug("[SCOPE_DEBUG] Found project_id query param: %s", projectID)
		userID := req.Header.Get("X-User-Id")
		scopes, err := keystoneDriver.UserProjects(ctx, userID)
		if err != nil {
			logg.Error("[SCOPE_DEBUG] UserProjects failed for user %s: %v", userID, err)
			panic(err)
		}
		// Membership is checked on the exact requested ID (a direct monitoring
		// role is required); children are then expanded to match the header
		// branch's semantics above. Range by index to avoid copying each
		// tokens.Scope (~72 bytes) per iteration.
		authorized := false
		for i := range scopes {
			if scopes[i].ProjectID == projectID {
				authorized = true
				break
			}
		}
		if !authorized {
			logg.Error("[SCOPE_DEBUG] User %s is not a member of requested project %s", userID, projectID)
			panic(fmt.Errorf("user is not authorized for project %q", projectID))
		}
		children, err := keystoneDriver.ChildProjects(ctx, projectID)
		if err != nil {
			logg.Error("[SCOPE_DEBUG] ChildProjects failed for %s: %v", projectID, err)
			panic(err)
		}
		allProjects := append([]string{projectID}, children...)
		return "project_id", appendSentinelValue(allProjects)
	}

	logg.Error("[SCOPE_DEBUG] No X-Project-Id or X-Domain-Id found in headers")
	panic(errors.New("missing OpenStack scope attributes in request header"))
}

// appendSentinelValue appends the configured global visibility sentinel to the label values list.
func appendSentinelValue(labelValues []string) []string {
	if sentinelValue != "" {
		return append(labelValues, sentinelValue)
	}
	return labelValues
}

// buildSelectors takes the selectors contained in the "match[]" URL query parameter(s)
// and extends them with a label-constrained for the project/domain scope
func buildSelectors(req *http.Request, keystoneDriver keystone.Driver) (*[]string, error) {
	labelKey, labelValues := scopeToLabelConstraint(req, keystoneDriver)

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
	filebytes, err := os.ReadFile(viper.GetString("keystone.policy_file"))
	if err != nil {
		panic(fmt.Errorf("policy file %s not found: %w", viper.GetString("keystone.policy_file"), err))
	}
	var rules map[string]string
	err = json.Unmarshal(filebytes, &rules)
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

func authorizeRules(keystoneDriver keystone.Driver, w http.ResponseWriter, req *http.Request, guessScope bool, rules []string) bool {
	logg.Debug("authenticate")
	matchedRules := []string{}

	domain, domainSet := mux.Vars(req)["domain"]

	// 1. check token cookies, then user-domain specified via path prefix or cookie
	cookie, cookieErr := req.Cookie(authTokenCookieName)
	cookieSet := false
	if cookieErr == nil && cookie.Value != "" && req.Header.Get(authTokenHeader) == "" {
		logg.Debug("found token cookie: %s...", cookie.String()[:1+len(cookie.String())/4])
		req.Header.Set(authTokenHeader, cookie.Value)
		cookieSet = true
	} else if isPlainBasicAuth(req) {
		// if username is not qualified and scoped we might need to cookie to interpret the username right
		if !domainSet {
			cookie, err := req.Cookie(userDomainCookieName)
			if err == nil && cookie.Value != "" && req.Header.Get(userDomainHeader) == "" {
				domain = cookie.Value
				domainSet = true
			}
			logg.Debug("setting user domain via cookie: %s", domain)
		} else {
			logg.Debug("setting user domain via URL: %s", domain)
		}
		req.Header.Set(userDomainHeader, domain)
	}

	// 2. authenticate
	ctx := req.Context()
	policyContext, err := keystoneDriver.AuthenticateRequest(ctx, req, guessScope)
	if err != nil {
		code := err.StatusCode()
		httpCode := http.StatusUnauthorized

		switch code {
		case keystone.StatusWrongCredentials:
			authFailuresCounter.Add(1)
			// expire the cookie and ask for new credentials if they are wrong
			username, _, ok := req.BasicAuth()
			if !ok {
				username = req.UserAgent()
			}
			logg.Info("Request with wrong credentials from %s: %s", username, err.Error())
			requestReauthentication(w)
		case keystone.StatusMissingCredentials:
			requestReauthentication(w)
		case keystone.StatusNoPermission:
			httpCode = http.StatusForbidden
		default:
			// warn of possible technical issues
			logg.Info("WARNING: Authentication error: %s", err.Error())
			authErrorsCounter.Add(1)
			httpCode = http.StatusInternalServerError
		}

		http.Error(w, err.Error(), httpCode)
		return false
	} else if domainSet && req.Header.Get("X-User-Domain-Name") != domain {
		// authentication was successful, but do the credentials match the given domain or do they perhaps belong to another user? we could not know in advance
		// either the basic authentication credentials or the cookie do not match the domain in the URL
		if cookieSet {
			// there is a cookie: clear it and ask for new credentials
			logg.Debug("User domain mismatch between %s (cookie with token) and %s (URL)", req.Header.Get("X-User-Domain-Name"), domain)
			requestReauthentication(w)
			http.Error(w, "User switch: please login again", http.StatusUnauthorized)
		} else {
			// redirect to new UI — domain mismatch is irrelevant now that
			// the expression browser is gone; credentials are still valid
			http.Redirect(w, req, "/ui/query", http.StatusFound)
		}
		return false
	}

	// 3. authorize
	pe := policyEngine()
	for _, rule := range rules {
		if pe.Enforce(rule, *policyContext) {
			matchedRules = append(matchedRules, rule)
		}
	}

	if len(matchedRules) == 0 {
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
		http.Error(w, html.EscapeString(fmt.Sprintf("User %s@%s does not have monitoring permissions on %s (actual roles: %s, required roles: %s)", username, userDomain, scope, actRoles, reqRoles)), http.StatusForbidden)

		return false
	}

	// set cookie
	setAuthCookies(req, w)

	return true
}

func requestReauthentication(w http.ResponseWriter) {
	logg.Debug("expire cookie and request username/password input")
	http.SetCookie(w, &http.Cookie{
		Name:     authTokenCookieName,
		Path:     "/",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("WWW-Authenticate", "Basic")
}

func setAuthCookies(req *http.Request, w http.ResponseWriter) {
	token := req.Header.Get(authTokenHeader)
	if token == "" {
		logg.Info("WARNING: X-Auth-Token Header is empty!?")
		return
	}
	logg.Debug("Setting cookie: %s...", token[1:len(token)/4])
	expiryStr := req.Header.Get(authTokenExpiryHeader)
	expiry, pErr := time.Parse(time.RFC3339Nano, expiryStr)
	if pErr != nil {
		logg.Info("WARNING: Incompatible token format for expiry data: %s", expiryStr)
		expiry = time.Now().UTC().Add(viper.GetDuration("keystone.token_cache_time"))
	}
	// set token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     authTokenCookieName,
		Path:     "/",
		Value:    token,
		Expires:  expiry.UTC(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	// remember domain as cookie so that reauthentication during Prometheus API calls (no domain prefix)
	// works with plain username and password.
	// HttpOnly is intentionally false: this carries only a domain name (no
	// secret), and the React UI reads it via document.cookie to build the
	// correct /{domain}/graph login redirect on a 401. The token cookie above
	// stays HttpOnly. Secure + SameSite=Lax remain set.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: domain name is not a secret and must be JS-readable for the login redirect; Secure+SameSite still set
		Name:     userDomainCookieName,
		Path:     "/",
		Value:    req.Header.Get(userDomainHeader),
		MaxAge:   60 * 60 * 24,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// authenticateOnly runs Keystone authentication but skips policy enforcement.
// Use for endpoints that return identity data rather than metric data.
func authenticateOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ks := getKeystoneFromContext(req.Context())
		if ks == nil {
			http.Error(w, "Internal server error: keystone context not available", http.StatusInternalServerError)
			logg.Error("Missing keystone context - request may have bypassed keystoneResolutionMiddleware")
			return
		}
		// Mirror the cookie→header logic from authorizeRules so token cookies work here too.
		if cookie, err := req.Cookie(authTokenCookieName); err == nil && cookie.Value != "" && req.Header.Get(authTokenHeader) == "" {
			req.Header.Set(authTokenHeader, cookie.Value)
		}
		_, authErr := ks.AuthenticateRequest(req.Context(), req, false)
		if authErr != nil {
			ReturnPromError(w, authErr, http.StatusUnauthorized)
			return
		}
		next(w, req)
	}
}

func authorize(wrappedHandlerFunc func(w http.ResponseWriter, req *http.Request),
	guessScope bool, rule string) func(w http.ResponseWriter, req *http.Request) {

	return func(w http.ResponseWriter, req *http.Request) {
		// Get keystone from context (secure, race-condition-free approach)
		ks := getKeystoneFromContext(req.Context())
		if ks == nil {
			// Context-based keystone resolution is mandatory for security
			// All requests must go through keystoneResolutionMiddleware
			http.Error(w, "Internal server error: keystone context not available", http.StatusInternalServerError)
			logg.Error("Missing keystone context - request may have bypassed keystoneResolutionMiddleware")
			return
		}
		if authorizeRules(ks, w, req, guessScope, []string{rule}) {
			wrappedHandlerFunc(w, req)
		}
	}
}

// keystoneResolutionMiddleware determines keystone type early and consistently
// This middleware eliminates race conditions by resolving keystone selection
// once at the beginning of request processing and storing it in request context.
func keystoneResolutionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DEBUG: Log incoming request details
		logg.Debug("[KEYSTONE_DEBUG] Processing request: %s %s", r.Method, r.URL.Path)
		logg.Debug("[KEYSTONE_DEBUG] X-Project-Id header: %s", r.Header.Get("X-Project-Id"))
		logg.Debug("[KEYSTONE_DEBUG] X-Auth-Token present: %t", r.Header.Get("X-Auth-Token") != "")
		logg.Debug("[KEYSTONE_DEBUG] Global param: %s", r.URL.Query().Get("global"))

		// Determine keystone type early and consistently
		keystoneType, keystoneDriver, err := determineKeystoneForRequest(r)
		if err != nil {
			logg.Error("Keystone resolution failed: %v", err)
			http.Error(w, fmt.Sprintf("Configuration error: %v", err), http.StatusServiceUnavailable)
			return
		}

		// Set both type and instance in request context
		ctx := context.WithValue(r.Context(), keystoneTypeKey, keystoneType)
		ctx = context.WithValue(ctx, keystoneInstanceKey, keystoneDriver)

		logg.Debug("[KEYSTONE_DEBUG] Request routed to %s keystone", keystoneType)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// determineKeystoneForRequest provides robust keystone determination with validation
// This function implements the core logic for selecting regional vs global keystone
// and includes proper error handling for invalid global flags.
func determineKeystoneForRequest(r *http.Request) (string, keystone.Driver, error) {
	// Parse global flag with proper validation
	isGlobal, err := parseGlobalRequest(r)
	if err != nil {
		return "", nil, fmt.Errorf("invalid global parameter: %w", err)
	}

	if isGlobal {
		if globalKeystoneInstance == nil {
			return "", nil, errors.New("global keystone requested but not configured")
		}
		return "global", globalKeystoneInstance, nil
	}

	return "regional", keystoneInstance, nil
}

// parseGlobalRequest handles robust boolean parsing with multiple formats
// It supports both URL parameters and headers with proper precedence.
func parseGlobalRequest(r *http.Request) (bool, error) {
	// Precedence: URL parameter > Header > default false
	if param := r.URL.Query().Get("global"); param != "" {
		return parseBoolean(param, "global parameter")
	}

	if header := r.Header.Get("X-Global-Region"); header != "" {
		return parseBoolean(header, "X-Global-Region header")
	}

	return false, nil
}

// parseBoolean provides robust boolean parsing with multiple accepted formats
func parseBoolean(value, source string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off", "":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value in %s: '%s'", source, value)
	}
}

// getKeystoneFromContext retrieves the keystone instance from request context
// This is the secure, thread-safe way to get keystone instances throughout request processing.
func getKeystoneFromContext(ctx context.Context) keystone.Driver {
	if driver, ok := ctx.Value(keystoneInstanceKey).(keystone.Driver); ok {
		return driver
	}
	// Return nil to indicate context-based keystone not available
	// Caller should handle fallback logic
	return nil
}

// getKeystoneTypeFromContext retrieves the keystone type from request context
func getKeystoneTypeFromContext(ctx context.Context) string {
	if keystoneType, ok := ctx.Value(keystoneTypeKey).(string); ok {
		return keystoneType
	}
	return "regional"
}

func gaugeInflight(handler http.Handler) http.Handler {
	inflightGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "maia_requests_inflight", Help: "Number of inflight HTTP requests served by Maia"})
	prometheus.MustRegister(inflightGauge)

	return promhttp.InstrumentHandlerInFlight(inflightGauge, handler)
}

// countRequests increments requestsTotal with the response code. It is wired
// OUTSIDE authorize() at the call sites so that auth rejections (401/403) are
// counted too — otherwise the counter would miss exactly the failures an error
// rate needs.
func countRequests(handlerFunc http.HandlerFunc, handler string) http.HandlerFunc {
	curried := requestsTotal.MustCurryWith(prometheus.Labels{"handler": handler})
	return promhttp.InstrumentHandlerCounter(curried, handlerFunc)
}

func observeDuration(handlerFunc http.HandlerFunc, handler string) http.HandlerFunc {
	// Explicit buckets with a boundary at 3s so the OpenstackMaiaResponsiveness
	// alert (p99 > 3) reads a real bucket edge instead of interpolating across the
	// DefBuckets gap between 2.5 and 5. The 30s/60s tail keeps resolution for slow
	// query_range calls that would otherwise all land in +Inf.
	durationHistogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "maia_request_duration_seconds", Help: "Duration/latency of a Maia request", Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 3, 5, 10, 30, 60}, ConstLabels: prometheus.Labels{"handler": handler}}, nil)
	prometheus.MustRegister(durationHistogram)

	return promhttp.InstrumentHandlerDuration(durationHistogram, handlerFunc)
}

func observeResponseSize(handlerFunc http.HandlerFunc, handler string) http.HandlerFunc {
	sizeHistogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "maia_response_size_bytes", Help: "Size of the Maia response (e.g. to a query)", Buckets: prometheus.ExponentialBuckets(100, 10, 7), ConstLabels: prometheus.Labels{"handler": handler}}, nil)
	prometheus.MustRegister(sizeHistogram)

	return promhttp.InstrumentHandlerResponseSize(sizeHistogram, handlerFunc).ServeHTTP
}
