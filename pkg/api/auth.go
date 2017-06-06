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

type BasicAuth struct {
	Username  string
	ProjectId string
	DomainId  string
	Password  string
	err       error
}

func (b *BasicAuth) String() string {
	username := "None"
	scope := "None"
	password := "None"

	if b.Username != "" {
		username = b.Username
	}

	if b.ProjectId != "" {
		scope = fmt.Sprintf("projectId: %s", b.ProjectId)
	} else if b.DomainId != "" {
		scope = fmt.Sprintf("domainId: %s", b.DomainId)
	}

	if b.Password != "" {
		password = "<hidden>"
	}

	return fmt.Sprintf("username: %s \n%s \npassword: %s", username, scope, password)
}

// Get credentials from Authorization header provided by Prometheus basic_auth
func (p *v1Provider) CheckBasicAuth(r *http.Request) *BasicAuth {

	username := ""
	scopeId := ""
	password := ""

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return &BasicAuth{err: errors.New("Authorization header missing")}
	}
	// example authHeader: Basic base64enc(user:password)
	basicAuthHeader, _ := base64.StdEncoding.DecodeString(strings.Fields(authHeader)[1])

	basicAuth := strings.Split(string(basicAuthHeader), ":")

	if len(basicAuth) != 2 {
		util.LogError("Insufficient parameters for basic authentication. Provide user@project and password")
		return nil
	}

	password = basicAuth[1]

	a := strings.Split(basicAuth[0], "@")

	if len(a) == 2 {
		if a[0] != "" {
			username = a[0]
		}
		if a[1] != "" {
			scopeId = a[1]
		}
	}

	//TODO: only project for now
	return &BasicAuth{Username: username, ProjectId: scopeId, Password: password}
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

func (p *v1Provider) GetToken(auth *BasicAuth) *Token {
	p.keystone.SetAuthOptions(auth.Username, auth.Password, auth.ProjectId)
	t := &Token{enforcer: viper.Get("maia.PolicyEnforcer").(*policy.Enforcer)}
	t.context, t.err = p.keystone.Authenticate(p.keystone.AuthOptions())
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

	if os.Getenv("DEBUG") == "1" {
		t.context.Logger = log.Printf //or any other function with the same signature
	}
	if !t.enforcer.Enforce(rule, t.context) {
		http.Error(w, "Unauthorized", 403)
		return false
	}
	return true
}
