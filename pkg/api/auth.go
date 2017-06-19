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

//BasicAuth represents a user authorization passed trough by a base64 encoded Authorization header of a request.
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
	scope 	 := "None"
	password := "None"

	if b.TokenID != "" {
		return fmt.Sprintf("tokenID: %s", b.TokenID)
	}
	if b.Username != "" {
		username = b.Username
	}

	if b.ProjectID != "" {
		scope = fmt.Sprintf("projectId: %s", b.ProjectID)
	} else if b.DomainID != "" {
		scope = fmt.Sprintf("domainId: %s", b.DomainID)
	}

	if b.Password != "" {
		password = "<hidden>"
	}

	return fmt.Sprintf("username: %s \n%s \npassword: %s", username, scope, password)
}

type handlerFunc func(w http.ResponseWriter, req *http.Request)

// Decorate HandlerFunc with authentication and authorization checks
func AuthorizedHandlerFunc(wrappedHandlerFunc func(w http.ResponseWriter, req *http.Request, projectID string), keystone keystone.Driver, rule string) handlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		util.LogInfo("authenticate")

		// get basic authentication credentials
		auth := CheckBasicAuth(req)
		if auth.err != nil {
			util.LogError(auth.err.Error())
			ReturnError(w, auth.err, 404)
			return
		}

		tenantId := ""
		if auth != nil {
			util.LogInfo(auth.String())
			if auth.ProjectID != "" {
				tenantId = auth.ProjectID
			} else if auth.DomainID != "" {
				tenantId = auth.DomainID
			} else {
				util.LogError("No project_id or domain_id found. Aborting.")
				ReturnError(w, auth.err, 404)
				return
			}
		}

		util.LogInfo("authorize for project/domain: %s .", tenantId)

		// authorize call
		token := GetTokenFromBasicAuth(auth, keystone)
		if token.err != nil {
			util.LogError(token.err.Error())
			ReturnError(w, token.err, 403)
			return
		}

		//TODO: cache and check token instead of always sending requests
		// token = CheckToken(req, keystone)

		if err := token.Require(rule); err != nil {
			util.LogError(err.Error())
			ReturnError(w, err, 403)
			return
		}

		// do it!
		wrappedHandlerFunc(w, req, auth.ProjectID)
	}
}

// Get credentials from Authorization header provided by Prometheus basic_auth
func CheckBasicAuth(r *http.Request) *BasicAuth {

	userID := ""
	scopeID := ""
	password := ""
	tokenID := ""

	username, password, ok := r.BasicAuth()
	if ok != true {
		return &BasicAuth{err: errors.New("Authorization header missing")}
	}
	usernameParts := strings.Split(username, "@")

	if len(basicAuth) != 2 {
		return &BasicAuth{err: errors.New("Insufficient parameters for basic authentication. Provide user_id@project_id and password or token@tokenID")}
	}

	password = basicAuth[1]

	user := strings.Split(basicAuth[0], "@")

	if len(user) != 2 {
		util.LogError("Insufficient parameters for basic authentication. Provide user@project and password")
		return &BasicAuth{err: errors.New("Insufficient parameters for basic authentication. Provide user@project and password")}
	}

	userID = user[0]
	scopeID = user[1]

	// authentication using token
	if strings.ToLower(userID) == "token" {
		util.LogDebug("Authenticate using token")
		tokenID = basicAuth[1]
		if tokenID == "" {
			return &BasicAuth{err: errors.New("Tried token based authentication with empty tokenID.")}
		}
		return &BasicAuth{TokenID: tokenID}
	}

	util.LogDebug("Authenticate using credentials")

	// authentication using username,projectid and password

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

func (p *v1Provider) GetTokenFromBasicAuth(auth *BasicAuth) *Token {
	var authOpts *gophercloud.AuthOptions
	if auth.TokenID != "" {
		authOpts = p.keystone.AuthOptionsFromBasicAuthToken(auth.TokenID)
	} else {
		authOpts = p.keystone.AuthOptionsFromBasicAuthCredentials(auth.UserID, auth.Password, auth.ProjectID)
	}
	t := &Token{enforcer: viper.Get("maia.PolicyEnforcer").(*policy.Enforcer)}
	t.context, t.err = p.keystone.AuthenticateUser(authOpts)
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
		util.LogInfo("User %s does not fulfill authorization rule %s", t.context.Auth, rule)
		return errors.New("Unauthorized")
	}
	return nil
}
