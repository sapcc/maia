// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package keystone

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	policy "github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud/v2"
	"github.com/h2non/gock"
	cache "github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const (
	baseURL      = "http://identity.local"
	serviceToken = "gAAAAABZjCvLtw2v36P_Nwn23Vkjl9ZIxK27YsVuGp2_bftQI6RfymVTvnLE_wNtrAzEJSg6Xa7Aoe37DgDp2wrryWs3klgSqjC7ecC6RD9hRxSaQsjd7choIjQVdIbZjph4vmhJzg7cPIQd9CT7x12wNKBYwIbAmCDFEX_CIlzmPXBUyeISI-M" //nolint:gosec // not real credential
	userToken    = "gUUUUUUZjCvLtw2v36P_Nwn23Vkjl9ZIxK27YsVuGp2_bftQI6RfymVTvnLE_wNtrAzEJSg6Xa7Aoe37DgDp2wrryWs3klgSqjC7ecC6RD9hRxSaQsjd7choIjQVdIbZjph4vmhJzg7cPIQd9CT7x12wNKBYwIbAmCDFEX_CIlzmPXBUyeISI-M" //nolint:gosec // not real credential
)

var serviceAuthBody = map[string]any{
	"auth": map[string]any{
		"identity": map[string]any{
			"methods": []any{
				"password",
			},
			"password": map[string]any{
				"user": map[string]any{
					"domain": map[string]any{
						"name": "Default",
					},
					"name":     "maia",
					"password": "maiatestPW",
				},
			},
		},
		"scope": map[string]any{
			"project": map[string]any{
				"domain": map[string]any{
					"name": "Default",
				},
				"name": "service",
			},
		},
	},
}
var userAuthBody = map[string]any{
	"auth": map[string]any{
		"identity": map[string]any{
			"methods": []any{
				"password",
			},
			"password": map[string]any{
				"user": map[string]any{
					"domain": map[string]any{
						"name": "testdomain",
					},
					"name":     "testuser",
					"password": "testpw",
				},
			},
		},
		"scope": map[string]any{
			"project": map[string]any{
				"domain": map[string]any{
					"name": "testdomain",
				},
				"name": "testproject",
			},
		},
	},
}

var userAuthScopeBody = map[string]any{
	"auth": map[string]any{
		"identity": map[string]any{
			"methods": []any{
				"password",
			},
			"password": map[string]any{
				"user": map[string]any{
					"domain": map[string]any{
						"name": "testdomain",
					},
					"name":     "testuser",
					"password": "testpw",
				},
			},
		},
		"scope": map[string]any{
			"project": map[string]any{
				"id": "p00001",
			},
		},
	},
}

func setupTest() Driver {
	// load test policy (where everything is allowed)
	viper.Set("maia.auth_driver", "keystone")
	viper.Set("maia.label_value_ttl", "72h")
	viper.Set("keystone.auth_url", baseURL+"/v3")
	viper.Set("keystone.username", "maia")
	viper.Set("keystone.password", "maiatestPW")
	viper.Set("keystone.user_domain_name", "Default")
	viper.Set("keystone.project_name", "service")
	viper.Set("keystone.project_domain_name", "Default")
	viper.Set("keystone.policy_file", "../test/policy.json")
	viper.Set("keystone.roles", "monitoring_admin,monitoring_viewer")

	// create test driver with the domains and projects from start-data.sql
	gock.New(baseURL).Post("/v3/auth/tokens").JSON(serviceAuthBody).Reply(http.StatusCreated).File("fixtures/service_token_create.json").AddHeader("X-Subject-Token", serviceToken)
	gock.New(baseURL).Get("/v3/roles").HeaderPresent("X-Auth-Token").Reply(http.StatusOK).File("fixtures/all_roles.json")
	// the projects-client does not imply that the response is JSON --> this leads to some confusion when the content-type header is missing from the response
	gock.New(baseURL).Get("/v3/projects").MatchParams(map[string]string{"enabled": "true", "is_domain": "true"}).HeaderPresent("X-Auth-Token").Reply(http.StatusOK).File("fixtures/all_domains.json").AddHeader("Content-Type", "application/json")
	return NewKeystoneDriver()
}

func mocksToStrings(mocks []gock.Mock) []string {
	s := make([]string, len(mocks))
	for i, m := range mocks {
		r := m.Request()
		s[i] = r.Method + " " + r.URLStruct.String()
	}
	return s
}

func TestNewKeystoneDriver(t *testing.T) {
	defer gock.Off()

	setupTest()

	assertDone(t)
}
func assertDone(t *testing.T) bool { //nolint:unparam
	return assert.True(t, gock.IsDone(), "pending mocks: %v\nunmatched requests: %v", mocksToStrings(gock.Pending()), gock.GetUnmatchedRequests())
}

func TestChildProjects(t *testing.T) {
	defer gock.Off()

	ks := setupTest()

	ctx := t.Context()

	gock.New(baseURL).Get("/v3/projects").MatchParams(map[string]string{"enabled": "true", "parent_id": "p00001"}).HeaderPresent("X-Auth-Token").Reply(http.StatusOK).File("fixtures/child_projects.json").AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Get("/v3/projects").MatchParams(map[string]string{"enabled": "true", "parent_id": "p00002"}).HeaderPresent("X-Auth-Token").Reply(http.StatusOK).BodyString("{ \"projects\": [] }").AddHeader("Content-Type", "application/json")

	ids, err := ks.ChildProjects(ctx, "p00001")

	assert.Nil(t, err, "ChildProjects should not return error")
	assert.EqualValues(t, []string{"p00002"}, ids)

	assertDone(t)
}

// counterVecValue reads the current value of a CounterVec child selected by its
// "cache" label, collecting directly from the collector (registry-independent).
func counterVecValue(vec *prometheus.CounterVec, cacheLabel string) float64 {
	ch := make(chan prometheus.Metric, 64)
	vec.Collect(ch)
	close(ch)
	for m := range ch {
		var dm dto.Metric
		if m.Write(&dm) != nil {
			continue
		}
		for _, lp := range dm.Label {
			if lp.GetName() == "cache" && lp.GetValue() == cacheLabel {
				return dm.Counter.GetValue()
			}
		}
	}
	return 0
}

func TestChildProjectsCacheMetrics(t *testing.T) {
	defer gock.Off()

	ks := setupTest()

	ctx := t.Context()

	gock.New(baseURL).Get("/v3/projects").MatchParams(map[string]string{"enabled": "true", "parent_id": "p00001"}).HeaderPresent("X-Auth-Token").Reply(http.StatusOK).File("fixtures/child_projects.json").AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Get("/v3/projects").MatchParams(map[string]string{"enabled": "true", "parent_id": "p00002"}).HeaderPresent("X-Auth-Token").Reply(http.StatusOK).BodyString("{ \"projects\": [] }").AddHeader("Content-Type", "application/json")

	missBefore := counterVecValue(keystoneCacheMisses, "project_tree")
	hitBefore := counterVecValue(keystoneCacheHits, "project_tree")

	// first lookup: cache miss, fetched from keystone (consumes both gock mocks)
	_, err := ks.ChildProjects(ctx, "p00001")
	assert.NoError(t, err)
	// second lookup: served from cache, no HTTP call
	_, err = ks.ChildProjects(ctx, "p00001")
	assert.NoError(t, err)

	assert.Equal(t, missBefore+1, counterVecValue(keystoneCacheMisses, "project_tree"), "expected one project_tree cache miss")
	assert.Equal(t, hitBefore+1, counterVecValue(keystoneCacheHits, "project_tree"), "expected one project_tree cache hit")

	assertDone(t)
}

func TestTokenCacheMetrics(t *testing.T) {
	defer gock.Off()

	ks := setupTest()
	ctx := t.Context()

	// only one validation call: the second request must be served from the token cache
	gock.New(baseURL).Get("/v3/auth/tokens").Reply(http.StatusOK).File("fixtures/user_token_validate.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")

	missBefore := counterVecValue(keystoneCacheMisses, "token")
	hitBefore := counterVecValue(keystoneCacheHits, "token")

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "http://maia.local/federate", http.NoBody)
		req.Header.Set("X-Auth-Token", userToken)
		_, err := ks.AuthenticateRequest(ctx, req, false)
		assert.Nil(t, err, "AuthenticateRequest should not fail")
	}

	assert.Equal(t, missBefore+1, counterVecValue(keystoneCacheMisses, "token"), "first request should count one token cache miss")
	assert.Equal(t, hitBefore+1, counterVecValue(keystoneCacheHits, "token"), "second request should count exactly one token cache hit")

	assertDone(t)
}

func TestTokenCacheMetrics_rescope(t *testing.T) {
	defer gock.Off()

	ks := setupTest()
	ctx := t.Context()

	// validate the p00001-scoped token, rescope it to p00002, then validate the new token
	gock.New(baseURL).Get("/v3/auth/tokens").Reply(http.StatusOK).File("fixtures/user_token_validate.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Post("/v3/auth/tokens").Reply(http.StatusCreated).File("fixtures/user_token_create.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Get("/v3/auth/tokens").Reply(http.StatusOK).File("fixtures/user_token_validate.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")

	missBefore := counterVecValue(keystoneCacheMisses, "token")

	req := httptest.NewRequest(http.MethodGet, "http://maia.local/federate?project_id=p00002", http.NoBody)
	req.Header.Set("X-Auth-Token", userToken)
	_, err := ks.AuthenticateRequest(ctx, req, false)
	assert.Nil(t, err, "AuthenticateRequest should not fail")

	// one request is one lookup: the rescope and the validation of the minted
	// token are internal and must not count as extra misses
	assert.Equal(t, missBefore+1, counterVecValue(keystoneCacheMisses, "token"), "a rescoped request should count exactly one token cache miss")

	assertDone(t)
}

func TestTokenCacheMetrics_basicAuth(t *testing.T) {
	defer gock.Off()

	ks := setupTest()
	ctx := t.Context()

	// one token creation and one validation: the second request is served from the cache
	gock.New(baseURL).Post("/v3/auth/tokens").JSON(userAuthScopeBody).Reply(http.StatusCreated).File("fixtures/user_token_create.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Get("/v3/auth/tokens").Reply(http.StatusOK).File("fixtures/user_token_validate.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")

	missBefore := counterVecValue(keystoneCacheMisses, "token")
	hitBefore := counterVecValue(keystoneCacheHits, "token")

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "http://maia.local/federate", http.NoBody)
		req.SetBasicAuth("testuser@testdomain|p00001", "testpw")
		_, err := ks.AuthenticateRequest(ctx, req, false)
		assert.Nil(t, err, "AuthenticateRequest should not fail")
	}

	// the cold login validates the minted token internally; that must not count as a second miss
	assert.Equal(t, missBefore+1, counterVecValue(keystoneCacheMisses, "token"), "first login should count exactly one token cache miss")
	assert.Equal(t, hitBefore+1, counterVecValue(keystoneCacheHits, "token"), "second login should count exactly one token cache hit")

	assertDone(t)
}

func TestAuthenticateRequest(t *testing.T) {
	defer gock.Off()

	ks := setupTest()

	ctx := t.Context()

	gock.New(baseURL).Post("/v3/auth/tokens").JSON(userAuthBody).Reply(http.StatusCreated).File("fixtures/user_token_create.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Get("/v3/auth/tokens").Reply(http.StatusOK).File("fixtures/user_token_validate.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")

	req := httptest.NewRequest(http.MethodGet, "http://maia.local/federate", http.NoBody)
	req.SetBasicAuth("testuser@testdomain|testproject@testdomain", "testpw")
	// A client-supplied X-Roles must not be trusted: AuthenticateRequest should
	// clear it and replace it with the authenticated roles as a single header.
	req.Header.Set("X-Roles", "spoofed-admin")
	// Client-supplied scope headers must not be trusted either: they are the
	// tenant boundary used downstream by scopeToLabelConstraint. A forged
	// X-Project-Id / X-Domain-Id must be overwritten/cleared from the validated
	// token, never allowed to survive (cross-tenant IDOR otherwise).
	req.Header.Set("X-Project-Id", "victim-project")
	req.Header.Set("X-Domain-Id", "victim-domain")
	policyContext, err := ks.AuthenticateRequest(ctx, req, false)

	assert.Nil(t, err, "AuthenticateRequest should not fail")
	assert.EqualValues(t, []string{"monitoring_viewer"}, policyContext.Roles, "AuthenticateRequest should return the right roles in the context")

	// X-Roles is emitted as a single comma-joined header (consumers split on ","),
	// and the spoofed client value has been overwritten, not appended to.
	assert.EqualValues(t, []string{"monitoring_viewer"}, req.Header.Values("X-Roles"), "X-Roles should be a single header carrying only the authenticated roles")
	assert.Equal(t, "monitoring_viewer", req.Header.Get("X-Roles"), "X-Roles must not retain the client-supplied value")

	// The token is project-scoped (p00001): X-Project-Id must be replaced with the
	// authenticated project, and the forged X-Domain-Id must be cleared entirely.
	assert.Equal(t, "p00001", req.Header.Get("X-Project-Id"), "X-Project-Id must be set from the validated token, not the client")
	assert.Empty(t, req.Header.Get("X-Domain-Id"), "X-Domain-Id must be cleared for a project-scoped token, not retain the client value")

	assertDone(t)
}

func TestAuthenticateRequest_urlScope(t *testing.T) {
	defer gock.Off()

	ks := setupTest()
	ctx := t.Context()

	gock.New(baseURL).Post("/v3/auth/tokens").JSON(userAuthScopeBody).Reply(http.StatusCreated).File("fixtures/user_token_create.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Get("/v3/auth/tokens").Reply(http.StatusOK).File("fixtures/user_token_validate.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")

	req := httptest.NewRequest(http.MethodGet, "http://maia.local/testdomain/graph?project_id=p00001", http.NoBody)
	req.SetBasicAuth("testuser@testdomain", "testpw")
	policyContext, err := ks.AuthenticateRequest(ctx, req, false)

	assert.Nil(t, err, "AuthenticateRequest should not fail")
	assert.EqualValues(t, []string{"monitoring_viewer"}, policyContext.Roles, "AuthenticateRequest should return the right roles in the context")

	assertDone(t)
}

func TestAuthenticateRequest_token(t *testing.T) {
	defer gock.Off()

	ks := setupTest()
	ctx := t.Context()

	gock.New(baseURL).Get("/v3/auth/tokens").Reply(http.StatusOK).File("fixtures/user_token_validate.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")

	req := httptest.NewRequest(http.MethodGet, "http://maia.local/federate", http.NoBody)
	req.Header.Set("X-Auth-Token", userToken)
	policyContext, err := ks.AuthenticateRequest(ctx, req, false)

	assert.Nil(t, err, "AuthenticateRequest should not fail")
	assert.EqualValues(t, []string{"monitoring_viewer"}, policyContext.Roles, "AuthenticateRequest should return the right roles in the context")

	assertDone(t)
}

func TestAuthenticateRequest_tokenInQueryRemovedFromURL(t *testing.T) {
	defer gock.Off()

	tests := []struct {
		name     string
		rawQuery string
		wantURL  string
	}{
		{
			name:     "only x-auth-token",
			rawQuery: "x-auth-token=" + userToken,
			wantURL:  "",
		},
		{
			name:     "x-auth-token with other params",
			rawQuery: "match%5B%5D=up&x-auth-token=" + userToken + "&global=true",
			wantURL:  "global=true&match%5B%5D=up",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ks := setupTest()
			ctx := t.Context()

			gock.New(baseURL).Get("/v3/auth/tokens").Reply(http.StatusOK).File("fixtures/user_token_validate.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")

			req := httptest.NewRequest(http.MethodGet, "http://maia.local/federate?"+tc.rawQuery, http.NoBody)
			_, err := ks.AuthenticateRequest(ctx, req, false)

			assert.Nil(t, err, "AuthenticateRequest should not fail")
			assert.Equal(t, tc.wantURL, req.URL.RawQuery, "x-auth-token should be removed from r.URL.RawQuery")
			assert.Equal(t, userToken, req.Header.Get("X-Auth-Token"), "token should be relocated to header")

			assertDone(t)
		})
	}
}

func TestAuthenticateRequest_failed(t *testing.T) {
	defer gock.Off()

	ks := setupTest()
	ctx := t.Context()

	gock.New(baseURL).Post("/v3/auth/tokens").Reply(http.StatusForbidden)

	req := httptest.NewRequest(http.MethodGet, "http://maia.local/federate", http.NoBody)
	req.SetBasicAuth("testuser@testdomain|testproject@testdomain", "testpw")
	_, err := ks.AuthenticateRequest(ctx, req, false)

	assert.NotNil(t, err, "AuthenticateRequest should fail with error when Keystone responds with 4xx")

	assertDone(t)
}

func TestAuthenticateRequest_failedNoScope(t *testing.T) {
	defer gock.Off()

	ks := setupTest()
	ctx := t.Context()

	req := httptest.NewRequest(http.MethodGet, "http://maia.local/federate", http.NoBody)
	req.SetBasicAuth("testuser@testdomain", "testpw")
	_, err := ks.AuthenticateRequest(ctx, req, false)

	assert.NotNil(t, err, "AuthenticateRequest should fail with error when scope information is missing for /federate")

	assertDone(t)
}

func TestAuthenticateRequest_guessScope(t *testing.T) {
	defer gock.Off()

	ks := setupTest()
	ctx := t.Context()

	gock.New(baseURL).Get("/v3/users").MatchParams(map[string]string{"domain_id": "d00001", "enabled": "true", "name": "testuser"}).HeaderPresent("X-Auth-Token").Reply(http.StatusOK).File("fixtures/testuser.json").AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Get("/v3/role_assignments").MatchParams(map[string]string{"effective": "true", "user.id": "u00001"}).HeaderPresent("X-Auth-Token").Reply(http.StatusOK).File("fixtures/testuser_roles.json").AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Get("/v3/projects/p00001").HeaderPresent("X-Auth-Token").Reply(http.StatusOK).File("fixtures/testproject.json").AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Post("/v3/auth/tokens").JSON(userAuthScopeBody).Reply(http.StatusCreated).File("fixtures/user_token_create.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Get("/v3/auth/tokens").Reply(http.StatusOK).File("fixtures/user_token_validate.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")

	req := httptest.NewRequest(http.MethodGet, "http://maia.local/federate", http.NoBody)
	req.SetBasicAuth("testuser@testdomain", "testpw")
	policyContext, err := ks.AuthenticateRequest(ctx, req, true)

	assert.Nil(t, err, "AuthenticateRequest should not fail")
	assert.EqualValues(t, []string{"monitoring_viewer"}, policyContext.Roles, "AuthenticateRequest should return the right roles in the context")

	assertDone(t)
}

func TestGetAuthURL(t *testing.T) {
	// Test default config section
	viper.Set("keystone.auth_url", "http://keystone.default.svc/v3")

	ks := &keystone{}
	authURL := ks.getAuthURL()
	assert.Equal(t, "http://keystone.default.svc/v3", authURL, "getAuthURL should return default keystone auth_url")

	// Test with custom config section
	viper.Set("keystone.global.auth_url", "http://keystone.global.svc/v3")

	ksGlobal := &keystone{configSection: "global"}
	authURLGlobal := ksGlobal.getAuthURL()
	assert.Equal(t, "http://keystone.global.svc/v3", authURLGlobal, "getAuthURL should return global keystone auth_url when configSection is set")

	// Clean up
	viper.Set("keystone.auth_url", "")
	viper.Set("keystone.global.auth_url", "")
}

// TestContextualCacheKeys verifies that different keystone contexts generate different cache keys
func TestContextualCacheKeys(t *testing.T) {
	// Create regional and global keystone instances
	regionalKeystone := &keystone{configSection: ""}
	globalKeystone := &keystone{configSection: "global"}

	// Same auth options should generate different cache keys
	authOpts := gophercloud.AuthOptions{
		Username:   "testuser",
		Password:   "testpass",
		DomainName: "testdomain",
		Scope: &gophercloud.AuthScope{
			ProjectID: "testproject",
		},
	}

	regionalKey := regionalKeystone.authOpts2StringKey(authOpts)
	globalKey := globalKeystone.authOpts2StringKey(authOpts)

	assert.NotEqual(t, regionalKey, globalKey, "Cache keys must be different for different contexts")
	assert.Contains(t, regionalKey, "CTX:regional", "Regional cache key must contain regional context")
	assert.Contains(t, globalKey, "CTX:global", "Global cache key must contain global context")

	// Verify keys contain base authentication information
	assert.Contains(t, regionalKey, "testuser", "Cache key must contain username")
	assert.Contains(t, globalKey, "testuser", "Cache key must contain username")
}

// TestKeystoneContext verifies that getKeystoneContext returns correct context
func TestKeystoneContext(t *testing.T) {
	// Test regional keystone (empty configSection)
	regionalKeystone := &keystone{configSection: ""}
	assert.Equal(t, "regional", regionalKeystone.getKeystoneContext(), "Empty configSection should return 'regional'")
	// Test global keystone
	globalKeystone := &keystone{configSection: "global"}
	assert.Equal(t, "global", globalKeystone.getKeystoneContext(), "Global configSection should return 'global'")
	// Test custom keystone section
	customKeystone := &keystone{configSection: "test"}
	assert.Equal(t, "test", customKeystone.getKeystoneContext(), "Custom configSection should return the section name")
}

// TestCacheIsolationWithContextualKeys verifies cache isolation between contexts
// Security Isolation Tests
// NOTE: These tests intentionally use explicit setup rather than loops/iterators
// to ensure complete isolation between regional and global keystone contexts.
// The duplication validates that no shared state or cache leakage can occur
// between different keystone instances - a critical security requirement.
func TestCacheIsolationWithContextualKeys(t *testing.T) {
	defer gock.Off()

	// Setup test configuration
	viper.Set("keystone.token_cache_time", "1h")

	// Create keystone instances with different contexts without full initialization
	// to avoid the authentication client initialization
	regionalKeystone := &keystone{configSection: ""}
	regionalKeystone.tokenCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)

	globalKeystone := &keystone{configSection: "global"}
	globalKeystone.tokenCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)

	// Test auth options
	authOpts := gophercloud.AuthOptions{
		Username:   "testuser",
		Password:   "testpass",
		DomainName: "testdomain",
		Scope: &gophercloud.AuthScope{
			ProjectID: "testproject",
		},
	}

	// Create mock cache entries
	regionalContext := &policy.Context{
		Auth: map[string]string{
			"user_id":    "regional-user-123",
			"project_id": "testproject",
		},
		Roles: []string{"regional_role"},
	}

	globalContext := &policy.Context{
		Auth: map[string]string{
			"user_id":    "global-user-456",
			"project_id": "testproject",
		},
		Roles: []string{"global_role"},
	}

	// Cache entries with different contexts
	regionalCacheKey := regionalKeystone.authOpts2StringKey(authOpts)
	globalCacheKey := globalKeystone.authOpts2StringKey(authOpts)

	regionalKeystone.tokenCache.Set(regionalCacheKey, &cacheEntry{
		context:     regionalContext,
		endpointURL: "http://regional.example.com",
	}, cache.DefaultExpiration)

	globalKeystone.tokenCache.Set(globalCacheKey, &cacheEntry{
		context:     globalContext,
		endpointURL: "http://global.example.com",
	}, cache.DefaultExpiration)

	// Verify regional keystone only sees regional cache entry
	regionalEntry, regionalFound := regionalKeystone.tokenCache.Get(regionalCacheKey)
	assert.True(t, regionalFound, "Regional keystone should find regional cache entry")
	assert.Equal(t, "regional-user-123", regionalEntry.(*cacheEntry).context.Auth["user_id"], "Regional cache should contain regional user")

	// Verify global keystone only sees global cache entry
	globalEntry, globalFound := globalKeystone.tokenCache.Get(globalCacheKey)
	assert.True(t, globalFound, "Global keystone should find global cache entry")
	assert.Equal(t, "global-user-456", globalEntry.(*cacheEntry).context.Auth["user_id"], "Global cache should contain global user")

	// Verify no cross-contamination: regional keystone cannot access global cache
	_, crossFound := regionalKeystone.tokenCache.Get(globalCacheKey)
	assert.False(t, crossFound, "Regional keystone should not find global cache entry")

	// Verify no cross-contamination: global keystone cannot access regional cache
	_, crossFound2 := globalKeystone.tokenCache.Get(regionalCacheKey)
	assert.False(t, crossFound2, "Global keystone should not find regional cache entry")
}

// TestConcurrentCacheAccess verifies thread safety with contextual cache keys
func TestConcurrentCacheAccess(t *testing.T) {
	viper.Set("keystone.token_cache_time", "1h")

	// Create keystone instances without full initialization
	regionalKeystone := &keystone{configSection: ""}
	regionalKeystone.tokenCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)

	globalKeystone := &keystone{configSection: "global"}
	globalKeystone.tokenCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)

	// Test concurrent access to different keystones
	var wg sync.WaitGroup
	iterations := 100

	// Regional keystone goroutines
	for i := range iterations {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			authOpts := gophercloud.AuthOptions{
				Username: fmt.Sprintf("regional-user-%d", idx),
				Password: "testpass",
				Scope: &gophercloud.AuthScope{
					ProjectID: fmt.Sprintf("project-%d", idx),
				},
			}
			cacheKey := regionalKeystone.authOpts2StringKey(authOpts)
			regionalKeystone.tokenCache.Set(cacheKey, &cacheEntry{
				context: &policy.Context{Auth: map[string]string{"user_id": fmt.Sprintf("regional-%d", idx)}},
			}, cache.DefaultExpiration)

			// Verify we can retrieve what we just set
			entry, found := regionalKeystone.tokenCache.Get(cacheKey)
			assert.True(t, found, "Should find cached entry")
			assert.Equal(t, fmt.Sprintf("regional-%d", idx), entry.(*cacheEntry).context.Auth["user_id"])
		}(i)
	}

	// Global keystone goroutines
	for i := range iterations {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			authOpts := gophercloud.AuthOptions{
				Username: fmt.Sprintf("global-user-%d", idx),
				Password: "testpass",
				Scope: &gophercloud.AuthScope{
					ProjectID: fmt.Sprintf("project-%d", idx),
				},
			}
			cacheKey := globalKeystone.authOpts2StringKey(authOpts)
			globalKeystone.tokenCache.Set(cacheKey, &cacheEntry{
				context: &policy.Context{Auth: map[string]string{"user_id": fmt.Sprintf("global-%d", idx)}},
			}, cache.DefaultExpiration)

			// Verify we can retrieve what we just set
			entry, found := globalKeystone.tokenCache.Get(cacheKey)
			assert.True(t, found, "Should find cached entry")
			assert.Equal(t, fmt.Sprintf("global-%d", idx), entry.(*cacheEntry).context.Auth["user_id"])
		}(i)
	}

	wg.Wait()
}

// TestSecurityVulnerabilityFixed demonstrates cache collision vulnerability prevention
func TestSecurityVulnerabilityFixed(t *testing.T) {
	// This test demonstrates the specific security issue that the code prevents:
	// Without context-aware keys, same credentials would generate identical cache keys across
	// different keystone instances, allowing authorization context injection

	viper.Set("keystone.token_cache_time", "1h")

	// Create keystone instances representing different contexts
	regionalKeystone := &keystone{configSection: ""}
	regionalKeystone.tokenCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)

	globalKeystone := &keystone{configSection: "global"}
	globalKeystone.tokenCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)

	// Simulated user credentials that could be used in both contexts
	maliciousAuthOpts := gophercloud.AuthOptions{
		Username:   "admin",
		Password:   "admin123",
		DomainName: "admin_domain",
		Scope: &gophercloud.AuthScope{
			ProjectID: "admin_project",
		},
	}

	// Simulate caching a high-privilege token in regional keystone
	regionalContext := &policy.Context{
		Auth: map[string]string{
			"user_id":             "regional-admin-123",
			"project_id":          "admin_project",
			"domain_id":           "admin_domain_id",
			"user_name":           "admin",
			"project_name":        "admin_project",
			"user_domain_name":    "admin_domain",
			"project_domain_name": "admin_domain",
		},
		Roles: []string{"admin", "cloud_admin"},
	}

	// Cache the high-privilege context in regional keystone
	regionalCacheKey := regionalKeystone.authOpts2StringKey(maliciousAuthOpts)
	regionalKeystone.tokenCache.Set(regionalCacheKey, &cacheEntry{
		context:     regionalContext,
		endpointURL: "http://regional.example.com",
	}, cache.DefaultExpiration)

	// Attempt to access the cached entry from global keystone using same credentials
	// This would succeed with vulnerable cache keys but fails with context-aware keys
	globalCacheKey := globalKeystone.authOpts2StringKey(maliciousAuthOpts)

	// Verify that global keystone cannot access regional cache entry
	_, foundFromGlobal := globalKeystone.tokenCache.Get(regionalCacheKey)
	assert.False(t, foundFromGlobal, "Global keystone should NOT find regional cache entries - vulnerability would allow this")

	// Verify that different contexts generate different cache keys (the core protection)
	assert.NotEqual(t, regionalCacheKey, globalCacheKey, "Cache keys MUST be different for different contexts")

	// Verify the keys contain the proper context markers
	assert.Contains(t, regionalCacheKey, "CTX:regional", "Regional cache key must be marked with regional context")
	assert.Contains(t, globalCacheKey, "CTX:global", "Global cache key must be marked with global context")

	// Cache something in global keystone with limited privileges
	globalContext := &policy.Context{
		Auth: map[string]string{
			"user_id":             "global-user-456",
			"project_id":          "limited_project",
			"domain_id":           "limited_domain_id",
			"user_name":           "admin",
			"project_name":        "limited_project",
			"user_domain_name":    "admin_domain",
			"project_domain_name": "limited_domain",
		},
		Roles: []string{"member"}, // Limited role
	}

	globalKeystone.tokenCache.Set(globalCacheKey, &cacheEntry{
		context:     globalContext,
		endpointURL: "http://global.example.com",
	}, cache.DefaultExpiration)

	// Verify complete isolation: each keystone can only access its own cached entries
	regionalEntry, regionalFound := regionalKeystone.tokenCache.Get(regionalCacheKey)
	assert.True(t, regionalFound, "Regional keystone should find its own cache entry")
	assert.Equal(t, "admin", regionalEntry.(*cacheEntry).context.Roles[0], "Regional should see admin role")

	globalEntry, globalFound := globalKeystone.tokenCache.Get(globalCacheKey)
	assert.True(t, globalFound, "Global keystone should find its own cache entry")
	assert.Equal(t, "member", globalEntry.(*cacheEntry).context.Roles[0], "Global should see member role")

	// Verification: regional keystone cannot access global cache
	_, crossAccess := regionalKeystone.tokenCache.Get(globalCacheKey)
	assert.False(t, crossAccess, "Regional keystone should NOT access global cache entries")

	// Verification: global keystone cannot access regional cache
	_, crossAccess2 := globalKeystone.tokenCache.Get(regionalCacheKey)
	assert.False(t, crossAccess2, "Global keystone should NOT access regional cache entries")

	t.Log("✓ Cache collision vulnerability prevented with context-aware cache keys")
	t.Log("✓ Authorization context injection prevention verified")
	t.Log("✓ Complete cache isolation between regional and global keystones confirmed")
}

// TestAuthenticateWithContextualCache demonstrates the authenticate method using contextual cache keys
func TestAuthenticateWithContextualCache(t *testing.T) {
	defer gock.Off()

	// Setup test configuration for both regional and global
	viper.Set("keystone.auth_url", baseURL+"/v3")
	viper.Set("keystone.global.auth_url", baseURL+"/v3")
	viper.Set("keystone.token_cache_time", "1h")

	// Create keystone instances
	regionalKeystone := &keystone{configSection: ""}
	regionalKeystone.tokenCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)

	globalKeystone := &keystone{configSection: "global"}
	globalKeystone.tokenCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)

	// Mock authentication responses for same credentials but different contexts
	authOpts := gophercloud.AuthOptions{
		Username:   "testuser",
		Password:   "testpass",
		DomainName: "testdomain",
		Scope: &gophercloud.AuthScope{
			ProjectID: "testproject",
		},
	}

	// Create mock cache entries directly to simulate authenticated users
	regionalContext := &policy.Context{
		Auth: map[string]string{
			"user_id":      "regional-user-123",
			"project_id":   "testproject",
			"user_name":    "testuser",
			"project_name": "testproject",
		},
		Roles: []string{"regional_role"},
	}

	globalContext := &policy.Context{
		Auth: map[string]string{
			"user_id":      "global-user-456",
			"project_id":   "testproject",
			"user_name":    "testuser",
			"project_name": "testproject",
		},
		Roles: []string{"global_role"},
	}

	// Cache the entries using contextual cache keys
	regionalCacheKey := regionalKeystone.authOpts2StringKey(authOpts)
	globalCacheKey := globalKeystone.authOpts2StringKey(authOpts)

	regionalKeystone.tokenCache.Set(regionalCacheKey, &cacheEntry{
		context:     regionalContext,
		endpointURL: "http://regional.example.com",
	}, cache.DefaultExpiration)

	globalKeystone.tokenCache.Set(globalCacheKey, &cacheEntry{
		context:     globalContext,
		endpointURL: "http://global.example.com",
	}, cache.DefaultExpiration)

	// Test cache retrieval through the authenticate method simulation
	// (We can't call authenticate directly without full mock setup, but we can test the cache logic)

	// Verify regional keystone gets regional context
	regionalEntry, regionalFound := regionalKeystone.tokenCache.Get(regionalCacheKey)
	assert.True(t, regionalFound, "Regional keystone should find cached entry")
	assert.Equal(t, "regional-user-123", regionalEntry.(*cacheEntry).context.Auth["user_id"], "Should get regional user context")
	assert.Equal(t, "http://regional.example.com", regionalEntry.(*cacheEntry).endpointURL, "Should get regional endpoint")

	// Verify global keystone gets global context
	globalEntry, globalFound := globalKeystone.tokenCache.Get(globalCacheKey)
	assert.True(t, globalFound, "Global keystone should find cached entry")
	assert.Equal(t, "global-user-456", globalEntry.(*cacheEntry).context.Auth["user_id"], "Should get global user context")
	assert.Equal(t, "http://global.example.com", globalEntry.(*cacheEntry).endpointURL, "Should get global endpoint")

	// Verify the fix: cache keys are different and prevent cross-access
	assert.NotEqual(t, regionalCacheKey, globalCacheKey, "Cache keys must be different")

	// Verify that each keystone can only see its own context
	_, cannotAccessGlobal := regionalKeystone.tokenCache.Get(globalCacheKey)
	assert.False(t, cannotAccessGlobal, "Regional keystone cannot access global cache")

	_, cannotAccessRegional := globalKeystone.tokenCache.Get(regionalCacheKey)
	assert.False(t, cannotAccessRegional, "Global keystone cannot access regional cache")

	t.Log("✓ Authenticate method contextual cache behavior verified")
	t.Log("✓ Cache isolation prevents authorization context leakage")
}

// fakeAssignmentsKeystone serves GET /v3/role_assignments the way Keystone does:
// it applies role.id first, then with include_names fails the whole request with
// 404 if any remaining assignment targets a domain object. Assignments are given
// as "roleID:projectID". It also serves GET /v3/projects/<id>.
func fakeAssignmentsKeystone(t *testing.T, assignments []string, domainObjects map[string]bool) *keystone {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v3/role_assignments", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		entries := []string{}
		for _, a := range assignments {
			roleID, projectID, _ := strings.Cut(a, ":")
			// Keystone applies the role.id filter before it resolves names.
			if q.Get("role.id") != "" && q.Get("role.id") != roleID {
				continue
			}
			if q.Get("include_names") == "true" && domainObjects[projectID] {
				http.Error(w, `{"error":{"code":404,"message":"Could not find domain: None."}}`, http.StatusNotFound)
				return
			}
			entries = append(entries, fmt.Sprintf(`{"role":{"id":%q},"scope":{"project":{"id":%q}}}`, roleID, projectID))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"role_assignments":[`+strings.Join(entries, ",")+`]}`)
	})
	mux.HandleFunc("GET /v3/projects/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"project":{"id":%q,"name":"name-%s","domain_id":"d00001","enabled":true}}`, id, id)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &keystone{
		providerClient: &gophercloud.ServiceClient{
			ProviderClient: &gophercloud.ProviderClient{},
			Endpoint:       srv.URL + "/v3/",
		},
		monitoringRoles:   map[string]string{"r00001": "monitoring_admin", "r00002": "monitoring_viewer"},
		domainNames:       map[string]string{"d00001": "testdomain"},
		projectScopeCache: cache.New(24*time.Hour, time.Hour),
	}
}

// TestFetchUserProjects_UnrelatedRoleOnDomainObject guards against listing role
// assignments with include_names for all roles: Keystone then fails the whole
// request if the user holds any role on a domain object, and Maia returned 500.
func TestFetchUserProjects_UnrelatedRoleOnDomainObject(t *testing.T) {
	d := fakeAssignmentsKeystone(t,
		[]string{"r00001:p00001", "radmin:dom0001", "r00002:p00002"},
		map[string]bool{"dom0001": true})

	scopes, err := d.fetchUserProjects(t.Context(), "u00001")

	if assert.NoError(t, err) && assert.Len(t, scopes, 2) {
		assert.Equal(t, "p00001", scopes[0].ProjectID)
		assert.Equal(t, "name-p00001", scopes[0].ProjectName)
		assert.Equal(t, "p00002", scopes[1].ProjectID)
	}
}

// TestFetchUserProjects_KeepsKeystoneOrder pins the result order to the order
// Keystone lists the assignments in. guessScope logs unscoped basic-auth users
// into the first project, so reordering would silently change their project.
func TestFetchUserProjects_KeepsKeystoneOrder(t *testing.T) {
	d := fakeAssignmentsKeystone(t,
		[]string{"r00002:p00003", "r00001:p00001", "r00002:p00002"}, nil)

	scopes, err := d.fetchUserProjects(t.Context(), "u00001")

	if assert.NoError(t, err) && assert.Len(t, scopes, 3) {
		assert.Equal(t, []string{"p00003", "p00001", "p00002"},
			[]string{scopes[0].ProjectID, scopes[1].ProjectID, scopes[2].ProjectID})
	}
}
