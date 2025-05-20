// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package keystone

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/h2non/gock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const (
	baseURL      = "http://identity.local"
	serviceToken = "gAAAAABZjCvLtw2v36P_Nwn23Vkjl9ZIxK27YsVuGp2_bftQI6RfymVTvnLE_wNtrAzEJSg6Xa7Aoe37DgDp2wrryWs3klgSqjC7ecC6RD9hRxSaQsjd7choIjQVdIbZjph4vmhJzg7cPIQd9CT7x12wNKBYwIbAmCDFEX_CIlzmPXBUyeISI-M" //nolint:gosec // not real credential
	userToken    = "gUUUUUUZjCvLtw2v36P_Nwn23Vkjl9ZIxK27YsVuGp2_bftQI6RfymVTvnLE_wNtrAzEJSg6Xa7Aoe37DgDp2wrryWs3klgSqjC7ecC6RD9hRxSaQsjd7choIjQVdIbZjph4vmhJzg7cPIQd9CT7x12wNKBYwIbAmCDFEX_CIlzmPXBUyeISI-M" //nolint:gosec // not real credential
)

var serviceAuthBody = map[string]interface{}{
	"auth": map[string]interface{}{
		"identity": map[string]interface{}{
			"methods": []interface{}{
				"password",
			},
			"password": map[string]interface{}{
				"user": map[string]interface{}{
					"domain": map[string]interface{}{
						"name": "Default",
					},
					"name":     "maia",
					"password": "maiatestPW",
				},
			},
		},
		"scope": map[string]interface{}{
			"project": map[string]interface{}{
				"domain": map[string]interface{}{
					"name": "Default",
				},
				"name": "service",
			},
		},
	},
}
var userAuthBody = map[string]interface{}{
	"auth": map[string]interface{}{
		"identity": map[string]interface{}{
			"methods": []interface{}{
				"password",
			},
			"password": map[string]interface{}{
				"user": map[string]interface{}{
					"domain": map[string]interface{}{
						"name": "testdomain",
					},
					"name":     "testuser",
					"password": "testpw",
				},
			},
		},
		"scope": map[string]interface{}{
			"project": map[string]interface{}{
				"domain": map[string]interface{}{
					"name": "testdomain",
				},
				"name": "testproject",
			},
		},
	},
}

var userAuthScopeBody = map[string]interface{}{
	"auth": map[string]interface{}{
		"identity": map[string]interface{}{
			"methods": []interface{}{
				"password",
			},
			"password": map[string]interface{}{
				"user": map[string]interface{}{
					"domain": map[string]interface{}{
						"name": "testdomain",
					},
					"name":     "testuser",
					"password": "testpw",
				},
			},
		},
		"scope": map[string]interface{}{
			"project": map[string]interface{}{
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

func TestAuthenticateRequest(t *testing.T) {
	defer gock.Off()

	ks := setupTest()

	ctx := t.Context()

	gock.New(baseURL).Post("/v3/auth/tokens").JSON(userAuthBody).Reply(http.StatusCreated).File("fixtures/user_token_create.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")
	gock.New(baseURL).Get("/v3/auth/tokens").Reply(http.StatusOK).File("fixtures/user_token_validate.json").AddHeader("X-Subject-Token", userToken).AddHeader("Content-Type", "application/json")

	req := httptest.NewRequest(http.MethodGet, "http://maia.local/federate", http.NoBody)
	req.SetBasicAuth("testuser@testdomain|testproject@testdomain", "testpw")
	policyContext, err := ks.AuthenticateRequest(ctx, req, false)

	assert.Nil(t, err, "AuthenticateRequest should not fail")
	assert.EqualValues(t, []string{"monitoring_viewer"}, policyContext.Roles, "AuthenticateRequest should return the right roles in the context")

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
