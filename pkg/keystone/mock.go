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

package keystone

import (
	"github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"net/http"
)

type mock struct{}

// Mock keystone implementation
func Mock() Driver {
	return mock{}
}

func (d mock) Authenticate(credentials *tokens.AuthOptions) (*policy.Context, string, error) {
	return &policy.Context{Request: map[string]string{"user_id": credentials.UserID,
		"project_id": credentials.Scope.ProjectID, "password": credentials.Password}}, "http://localhost:9091", nil
}

func (d mock) AuthenticateRequest(req *http.Request) (*policy.Context, error) {
	req.Header.Set("X-Project-Id", "12345")
	return &policy.Context{Request: map[string]string{"user_id": "testuser",
		"project_id": "12345", "password": "testwd"}, Auth: map[string]string{"project_id": "12345"}, Roles: []string{"monitoring_viewer"}}, nil
}

func (d mock) ChildProjects(projectID string) []string {
	return []string{}
}
