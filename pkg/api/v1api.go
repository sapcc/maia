// SPDX-FileCopyrightText: 2017 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/common/model"
	"github.com/sapcc/go-bits/logg"
	"github.com/spf13/viper"

	"github.com/SAP-cloud-infrastructure/maia/pkg/keystone"
	"github.com/SAP-cloud-infrastructure/maia/pkg/storage"
	"github.com/SAP-cloud-infrastructure/maia/pkg/util"
)

// class for Prometheus v1 API provider implementation
type v1Provider struct {
	keystone keystone.Driver
	storage  storage.Driver
}

// NewV1Handler creates a http.Handler that serves the Maia v1 API.
// It also returns the VersionData for this API version which is needed for the
// version advertisement on "GET /".
func NewV1Handler(keystoneDriver keystone.Driver, storageDriver storage.Driver) http.Handler {
	r := mux.NewRouter()
	p := &v1Provider{
		keystone: keystoneDriver,
		storage:  storageDriver,
	}

	// Note: Keystone resolution is handled by keystoneResolutionMiddleware at router level
	// This eliminates race conditions by ensuring consistent keystone selection throughout request lifecycle

	// identity endpoints (auth only, no policy enforcement)
	r.Methods(http.MethodGet).Path("/whoami").HandlerFunc(authenticateOnly(p.Whoami))
	r.Methods(http.MethodGet).Path("/projects").HandlerFunc(authenticateOnly(p.Projects))
	// metadata requires monitoring role — same as label values to prevent cross-tenant enumeration
	r.Methods(http.MethodGet).Path("/metadata").HandlerFunc(authorize(p.Metadata, false, "metric:list"))
	// MAIA: parse_query removed — not available on Thanos query frontends

	// tenant-aware query
	r.Methods(http.MethodGet).Path("/query").HandlerFunc(countRequests(authorize(
		observeDuration(observeResponseSize(p.Query, "query"), "query"),
		false,
		"metric:show"), "query"))
	// tenant-aware query range
	r.Methods(http.MethodGet).Path("/query_range").HandlerFunc(countRequests(authorize(
		observeDuration(observeResponseSize(p.QueryRange, "query_range"), "query_range"),
		false,
		"metric:show"), "query_range"))
	// tenant-aware label value lists
	r.Methods(http.MethodGet).Path("/label/{name}/values").HandlerFunc(countRequests(authorize(observeDuration(observeResponseSize(p.LabelValues, "label_values"), "label_values"), false, "metric:list"), "label_values"))
	// tenant-aware label name lists
	r.Methods(http.MethodGet).Path("/labels").HandlerFunc(countRequests(authorize(observeDuration(observeResponseSize(p.Labels, "labels"), "labels"), false, "metric:list"), "labels"))
	// tenant-aware series metadata
	r.Methods(http.MethodGet).Path("/series").HandlerFunc(countRequests(authorize(observeDuration(observeResponseSize(p.Series, "series"), "series"), false, "metric:list"), "series"))

	return r
}

func (p *v1Provider) Query(w http.ResponseWriter, req *http.Request) {
	ks := getKeystoneFromContext(req.Context())
	if ks == nil {
		ReturnPromError(w, errors.New("keystone context not available"), http.StatusInternalServerError)
		return
	}

	labelKey, labelValue := scopeToLabelConstraint(req, ks)

	queryParams := req.URL.Query()
	originalQuery := queryParams.Get("query")
	logg.Debug("[QUERY_DEBUG] Original query: %s", originalQuery)
	logg.Debug("[QUERY_DEBUG] Label constraint: %s = %v", labelKey, labelValue)

	newQuery, err := util.AddLabelConstraintToExpression(originalQuery, labelKey, labelValue)
	if err != nil {
		logg.Error("[QUERY_DEBUG] Query modification failed: %v", err)
		ReturnPromError(w, err, http.StatusBadRequest)
		return
	}

	logg.Debug("[QUERY_DEBUG] Modified query: %s", newQuery)
	resp, err := p.storage.Query(newQuery, queryParams.Get("time"), queryParams.Get("timeout"), req.Header.Get("Accept"))
	if err != nil {
		logg.Error("[QUERY_DEBUG] Storage query failed: %v", err)
		ReturnPromError(w, err, http.StatusServiceUnavailable)
		return
	}

	ReturnResponse(w, resp)
}

func (p *v1Provider) QueryRange(w http.ResponseWriter, req *http.Request) {
	ks := getKeystoneFromContext(req.Context())
	if ks == nil {
		ReturnPromError(w, errors.New("keystone context not available"), http.StatusInternalServerError)
		return
	}

	labelKey, labelValue := scopeToLabelConstraint(req, ks)

	queryParams := req.URL.Query()
	newQuery, err := util.AddLabelConstraintToExpression(queryParams.Get("query"), labelKey, labelValue)
	if err != nil {
		ReturnPromError(w, err, http.StatusBadRequest)
		return
	}

	resp, err := p.storage.QueryRange(newQuery, queryParams.Get("start"), queryParams.Get("end"), queryParams.Get("step"), queryParams.Get("timeout"), req.Header.Get("Accept"))
	if err != nil {
		ReturnPromError(w, err, http.StatusServiceUnavailable)
		return
	}

	ReturnResponse(w, resp)
}

// LabelValues utilizes the query range API in order to implement a tenant-aware list.
// This is a complex operation.
func (p *v1Provider) LabelValues(w http.ResponseWriter, req *http.Request) {
	name := model.LabelName(mux.Vars(req)["name"])
	// exclude label values from series that exceed maia.label_value_ttl age limit
	ttl, err := time.ParseDuration(viper.GetString("maia.label_value_ttl"))
	if err != nil {
		ReturnPromError(w, errors.New("invalid Maia configuration (maia.label_value_ttl)"), http.StatusInternalServerError)
		return
	}

	ks := getKeystoneFromContext(req.Context())
	if ks == nil {
		ReturnPromError(w, errors.New("keystone context not available"), http.StatusInternalServerError)
		return
	}

	// build project_id constraint using project hierarchy
	labelKey, labelValues := scopeToLabelConstraint(req, ks)
	// make a broad range query and aggregate by requested label. Use count() as cheap aggregation function.
	query, err := util.AddLabelConstraintToExpression("count({"+string(name)+"!=\"\"}) BY ("+string(name)+")", labelKey, labelValues)
	if err != nil {
		ReturnPromError(w, err, http.StatusBadRequest)
		return
	}

	start := time.Now().Add(-ttl)
	end := time.Now()
	// select step-size to return only two values (minimum and maximum)
	step := viper.GetString("maia.label_value_ttl")
	resp, err := p.storage.QueryRange(query, start.Format(time.RFC3339), end.Format(time.RFC3339), step, "", req.Header.Get("Accept"))
	if err != nil {
		ReturnPromError(w, err, http.StatusBadGateway)
		return
	}

	// read the complete result into memory
	// could this be avoided (streaming like in Java)?
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		ReturnPromError(w, err, resp.StatusCode)
		return
	}

	// unmarshal
	var sr storage.QueryResponse
	err = json.Unmarshal(buf, &sr)
	if err != nil {
		ReturnPromError(w, err, http.StatusInternalServerError)
		return
	}
	matrix, ok := sr.Data.Value.(model.Matrix)
	if !ok {
		ReturnPromError(w, fmt.Errorf("cannot process LabelValues response: expected matrix result type, got %s", sr.Data.Value.Type()), http.StatusBadGateway)
		return
	}

	// take just the label values from the query result
	var result storage.LabelValuesResponse
	result.Status = sr.Status
	result.Data = make(model.LabelValues, 0, len(matrix))
	for k := range matrix {
		metric := matrix[k]
		if metric != nil {
			result.Data = append(result.Data, metric.Metric[name])
		}
	}
	// sort the stuff (it's often on the UI)
	sort.Sort(result.Data)

	ReturnJSON(w, 200, &result)
}

func (p *v1Provider) Series(w http.ResponseWriter, req *http.Request) {
	ks := getKeystoneFromContext(req.Context())
	if ks == nil {
		ReturnPromError(w, errors.New("keystone context not available"), http.StatusInternalServerError)
		return
	}

	selectors, err := buildSelectors(req, ks)
	if err != nil {
		ReturnPromError(w, err, http.StatusBadRequest)
		return
	}
	queryParams := req.URL.Query()
	resp, err := p.storage.Series(*selectors, queryParams.Get("start"), queryParams.Get("end"), req.Header.Get("Accept"))
	if err != nil {
		ReturnPromError(w, err, http.StatusBadGateway)
		return
	}

	ReturnResponse(w, resp)
}

func (p *v1Provider) Labels(w http.ResponseWriter, req *http.Request) {
	ks := getKeystoneFromContext(req.Context())
	if ks == nil {
		ReturnPromError(w, errors.New("keystone context not available"), http.StatusInternalServerError)
		return
	}

	match, err := buildSelectors(req, ks)
	if err != nil {
		ReturnPromError(w, err, http.StatusBadRequest)
		return
	}

	queryParams := req.URL.Query()
	start := queryParams.Get("start")
	end := queryParams.Get("end")

	resp, err := p.storage.Labels(start, end, *match, req.Header.Get("Accept"))
	if err != nil {
		ReturnPromError(w, err, http.StatusServiceUnavailable)
		return
	}

	ReturnResponse(w, resp)
}

// MAIA: ParseQuery removed — parse_query endpoint not available on Thanos query frontends

func (p *v1Provider) Metadata(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	metricFilter := q.Get("metric")

	// If a specific metric is requested, proxy directly — the caller already
	// knows the name; no cross-tenant leak.
	if metricFilter != "" {
		resp, err := p.storage.Metadata(metricFilter, q.Get("limit"), req.Header.Get("Accept"))
		if err != nil {
			ReturnPromError(w, err, http.StatusServiceUnavailable)
			return
		}
		ReturnResponse(w, resp)
		return
	}

	// No metric filter: fetch all metadata from Prometheus, then restrict to
	// metric names the tenant can actually see (via label/__name__/values which
	// is already tenant-scoped via scopeToLabelConstraint).
	ks := getKeystoneFromContext(req.Context())
	if ks == nil {
		ReturnPromError(w, errors.New("keystone context not available"), http.StatusInternalServerError)
		return
	}
	labelKey, labelValues := scopeToLabelConstraint(req, ks)
	query, err := util.AddLabelConstraintToExpression(
		"count({__name__!=\"\"}) BY (__name__)", labelKey, labelValues)
	if err != nil {
		ReturnPromError(w, err, http.StatusBadRequest)
		return
	}

	ttl, err := time.ParseDuration(viper.GetString("maia.label_value_ttl"))
	if err != nil {
		ReturnPromError(w, errors.New("invalid Maia configuration (maia.label_value_ttl)"), http.StatusInternalServerError)
		return
	}
	start := time.Now().Add(-ttl)
	end := time.Now()
	namesResp, err := p.storage.QueryRange(query, start.Format(time.RFC3339), end.Format(time.RFC3339),
		viper.GetString("maia.label_value_ttl"), "", "application/json")
	if err != nil {
		ReturnPromError(w, err, http.StatusBadGateway)
		return
	}
	defer namesResp.Body.Close()
	buf, err := io.ReadAll(namesResp.Body)
	if err != nil {
		ReturnPromError(w, err, http.StatusInternalServerError)
		return
	}
	var qr storage.QueryResponse
	if err := json.Unmarshal(buf, &qr); err != nil {
		ReturnPromError(w, err, http.StatusInternalServerError)
		return
	}
	matrix, ok := qr.Data.Value.(model.Matrix)
	if !ok {
		ReturnPromError(w, errors.New("unexpected result type from metric name query"), http.StatusInternalServerError)
		return
	}
	allowed := make(map[string]bool, len(matrix))
	for _, s := range matrix {
		if n := string(s.Metric[model.MetricNameLabel]); n != "" {
			allowed[n] = true
		}
	}

	// Fetch all metadata from Prometheus (no metric filter, no limit).
	metaResp, err := p.storage.Metadata("", "", req.Header.Get("Accept"))
	if err != nil {
		ReturnPromError(w, err, http.StatusServiceUnavailable)
		return
	}
	defer metaResp.Body.Close()
	metaBuf, err := io.ReadAll(metaResp.Body)
	if err != nil {
		ReturnPromError(w, err, http.StatusInternalServerError)
		return
	}
	var raw struct {
		Status string                     `json:"status"`
		Data   map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(metaBuf, &raw); err != nil {
		ReturnPromError(w, err, http.StatusInternalServerError)
		return
	}
	// Filter: keep only metric names visible to this tenant.
	filtered := make(map[string]json.RawMessage, len(allowed))
	for name, meta := range raw.Data {
		if allowed[name] {
			filtered[name] = meta
		}
	}
	ReturnJSON(w, http.StatusOK, map[string]any{"status": "success", "data": filtered})
}

// whoamiResponse is the JSON shape returned by GET /api/v1/whoami.
type whoamiResponse struct {
	UserID         string   `json:"userId"`
	UserName       string   `json:"userName"`
	ProjectID      string   `json:"projectId"`
	ProjectName    string   `json:"projectName"`
	DomainID       string   `json:"domainId"`
	DomainName     string   `json:"domainName"`
	UserDomainName string   `json:"userDomainName"`
	Roles          []string `json:"roles"`
}

func (p *v1Provider) Whoami(w http.ResponseWriter, req *http.Request) {
	h := req.Header
	rolesRaw := h.Get("X-Roles")
	roles := []string{}
	if rolesRaw != "" {
		for r := range strings.SplitSeq(rolesRaw, ",") {
			if r = strings.TrimSpace(r); r != "" {
				roles = append(roles, r)
			}
		}
	}
	ReturnJSON(w, http.StatusOK, whoamiResponse{
		UserID:         h.Get("X-User-Id"),
		UserName:       h.Get("X-User-Name"),
		ProjectID:      h.Get("X-Project-Id"),
		ProjectName:    h.Get("X-Project-Name"),
		DomainID:       h.Get("X-Domain-Id"),
		DomainName:     h.Get("X-Domain-Name"),
		UserDomainName: h.Get("X-User-Domain-Name"),
		Roles:          roles,
	})
}

// projectEntry is a single project entry in the GET /api/v1/projects response.
type projectEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (p *v1Provider) Projects(w http.ResponseWriter, req *http.Request) {
	userID := req.Header.Get("X-User-Id")
	scopes, err := p.keystone.UserProjects(req.Context(), userID)
	if err != nil {
		ReturnPromError(w, err, http.StatusInternalServerError)
		return
	}
	// Deduplicate by project ID — a user may have multiple role assignments
	// on the same project, causing Keystone to return it more than once.
	seen := map[string]bool{}
	result := make([]projectEntry, 0, len(scopes))
	for _, s := range scopes {
		if seen[s.ProjectID] {
			continue
		}
		seen[s.ProjectID] = true
		result = append(result, projectEntry{ID: s.ProjectID, Name: s.ProjectName})
	}
	ReturnJSON(w, http.StatusOK, result)
}
