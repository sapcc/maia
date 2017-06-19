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

	base64 "encoding/base64"
	"fmt"
	policy "github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gorilla/mux"
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
		scope = fmt.Sprintf("projectID: %s", b.ProjectID)
	} else if b.DomainID != "" {
		scope = fmt.Sprintf("domainID: %s", b.DomainID)
	}

	if b.Password != "" {
		password = "<hidden>"
	}

	return fmt.Sprintf("username: %s \n%s \npassword: %s", username, scope, password)
}

// Get credentials from Authorization header provided by Prometheus basic_auth
func (p *v1Provider) CheckBasicAuth(r *http.Request) *BasicAuth {

	userID := ""
	scopeID := ""
	password := ""
	tokenID := ""

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return &BasicAuth{err: errors.New("Authorization header missing")}
	}
	// example authHeader: Basic base64enc(user@project:password) or base64enc(token:<token>)
	basicAuthHeader, _ := base64.StdEncoding.DecodeString(strings.Fields(authHeader)[1])

	basicAuth := strings.Split(string(basicAuthHeader), ":")

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
func (p *v1Provider) CheckToken(r *http.Request) *Token {
	str := r.Header.Get("X-Auth-Token")
	if str == "" {
		return &Token{err: errors.New("X-Auth-Token header missing")}
	}

	t := &Token{enforcer: viper.Get("maia.PolicyEnforcer").(*policy.Enforcer)}
	t.context, t.err = p.keystone.ValidateToken(str)
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
func (t *Token) Require(w http.ResponseWriter, rule string) bool {
	if t.err != nil {
		http.Error(w, t.err.Error(), 401)
		return false
	}

	if os.Getenv("MAIA_DEBUG") == "1" {
		t.context.Logger = log.Printf //or any other function with the same signature
	}
	if !t.enforcer.Enforce(rule, t.context) {
		http.Error(w, "Unauthorized", 403)
		return false
	}
	return true
}
