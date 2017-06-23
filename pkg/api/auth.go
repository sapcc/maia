/*******************************************************************************
*
* Copyright 2017 Stefan Majewsky <majewsky@gmx.net>
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
	"errors"
	"net/http"

	"log"
	"os"

	"fmt"
	policy "github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gorilla/mux"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"strings"
)

//Token represents a user's token, as passed through the X-Auth-Token header of
//a request.
type Token struct {
	enforcer *policy.Enforcer
	context  policy.Context
	err      error
}

// BasicAuth contains credentials coming from username/password login
type BasicAuth struct {
	UserID    string
	Username  string
	ProjectID string
	DomainID  string
	Password  string
	TokenID   string
	err       error
}

func (b *BasicAuth) String() string {
	username := "None"
	scope := "None"
	password := "None"

	if b.TokenID != "" {
		return fmt.Sprintf("tokenID: %s", b.TokenID)
	}
	if b.Username != "" {
		username = b.Username
	}

	if b.ProjectID != "" {
		scope = fmt.Sprintf("projectID: %s", b.ProjectID)
	} else if b.DomainID != "" {
		scope = fmt.Sprintf("domainID: %s", b.DomainID)
	}

	if b.Password != "" {
		password = "<hidden>"
	}

	return fmt.Sprintf("username: %s \n%s \npassword: %s", username, scope, password)
}

// AuthorizedHandlerFunc decorates a HandlerFunc with authentication and authorization checks
func AuthorizedHandlerFunc(wrappedHandlerFunc func(w http.ResponseWriter, req *http.Request, projectID string), keystone keystone.Driver, rule string) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		util.LogInfo("authenticate")

		// TODO implement basic auth
		// get basic authentication credentials
		auth := CheckBasicAuth(req)
		if auth.err != nil {
			util.LogError(auth.err.Error())
			ReturnError(w, auth.err, 401)
			return
		}

		tenantID := ""
		if auth != nil {
			util.LogInfo(auth.String())
			if auth.ProjectID != "" {
				tenantID = auth.ProjectID
			} else if auth.DomainID != "" {
				tenantID = auth.DomainID
			} else {
				util.LogError("No project_id or domain_id found. Aborting.")
				ReturnError(w, auth.err, 401)
				return
			}
		}

		util.LogInfo("authorize for project/domain: %s .", tenantID)

		// authorize call
		token := GetTokenFromBasicAuth(auth, keystone)
		if token.err != nil {
			util.LogError(token.err.Error())
			ReturnError(w, token.err, 403)
			return
		}

		//TODO: cache and check token instead of always sending requests
		//token = CheckToken(req, keystone)

		if err := token.Require(rule); err != nil {
			util.LogError(err.Error())
			ReturnError(w, err, 403)
			return
		}

		// do it!
		wrappedHandlerFunc(w, req, auth.ProjectID)
	}
}

// CheckBasicAuth performs login using username/password.
// It requires username to contain a qualified OpenStack username and project/domain scope information
// Format: <user>"|"<project or domain>
// user/project can either be a unique OpenStack ID or a qualified name with domain information, e.g. username"@"domain
func CheckBasicAuth(r *http.Request) *BasicAuth {

	userID := ""
	scopeID := ""
	password := ""

	userID, password, ok := r.BasicAuth()
	if ok != true {
		return &BasicAuth{err: errors.New("Authorization header missing")}
	}
	usernameParts := strings.Split(userID, "|")

	if len(usernameParts) != 2 {
		util.LogError("Insufficient parameters for basic authentication. Provide user-id|project-id and password")
		return &BasicAuth{err: errors.New("Insufficient parameters for basic authentication. Provide user-id|project-id and password")}
	}

	userID = usernameParts[0]
	scopeID = usernameParts[1]

	//TODO: only project for now. ask keystone, wether it's a project or domain
	return &BasicAuth{UserID: userID, ProjectID: scopeID, Password: password}
}

//CheckToken checks the validity of the request's X-Auth-Token in keystone, and
//returns a Token instance for checking authorization. Any errors that occur
//during this function are deferred until Require() is called.
func CheckToken(r *http.Request, keystone keystone.Driver) *Token {
	str := r.Header.Get("X-Auth-Token")
	if str == "" {
		return &Token{err: errors.New("X-Auth-Token header missing")}
	}

	t := &Token{enforcer: viper.Get("maia.PolicyEnforcer").(*policy.Enforcer)}
	t.context, t.err = keystone.ValidateToken(str)
	t.context.Request = mux.Vars(r)
	return t
}

// GetTokenFromBasicAuth creates an OpenStack token from a scoped username / password
func GetTokenFromBasicAuth(auth *BasicAuth, keystone keystone.Driver) *Token {
	var authOpts *gophercloud.AuthOptions
	if auth.TokenID != "" {
		authOpts = keystone.AuthOptionsFromBasicAuthToken(auth.TokenID)
	} else {
		authOpts = keystone.AuthOptionsFromBasicAuthCredentials(auth.UserID, auth.Password, auth.ProjectID)
	}
	t := &Token{enforcer: viper.Get("maia.PolicyEnforcer").(*policy.Enforcer)}
	t.context, t.err = keystone.AuthenticateUser(authOpts)
	return t
}

//Require checks if the given token has the given permission according to the
//policy.json that is in effect. If not, an error response is written and false
//is returned.
func (t *Token) Require(rule string) error {
	if os.Getenv("MAIA_DEBUG") == "1" {
		t.context.Logger = log.Printf //or any other function with the same signature
	}
	if !t.enforcer.Enforce(rule, t.context) {
		util.LogInfo("User %s with roles %s on project %s does not fulfill authorization rule %s", t.context.Auth["user_id"], t.context.Roles, t.context.Auth["project_id"], rule)
		return errors.New("Unauthorized")
	}
	return nil
}
