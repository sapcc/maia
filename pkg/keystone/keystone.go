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
	"fmt"

	"net/http"
	"net/url"
	"sync"

	"github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/pkg/errors"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"strings"
)

// Keystone creates a real keystone authentication and authorization driver
func Keystone() Driver {
	return keystone{}
}

type keystone struct {
	TokenRenewalMutex *sync.Mutex
}

var providerClient *gophercloud.ProviderClient

func (d keystone) keystoneClient(iServiceUser bool) (*gophercloud.ServiceClient, error) {
	if d.TokenRenewalMutex == nil {
		d.TokenRenewalMutex = &sync.Mutex{}
	}
	if providerClient == nil {
		var err error
		providerClient, err = openstack.NewClient(viper.GetString("keystone.auth_url"))
		if err != nil {
			return nil, fmt.Errorf("cannot initialize OpenStack client: %v", err)
		}

		if iServiceUser {
			err = d.refreshToken()
			if err != nil {
				return nil, fmt.Errorf("cannot fetch initial Keystone token: %v", err)
			}
		}
	}

	if viper.IsSet("maia.proxy") {
		proxyURL, err := url.Parse(viper.GetString("maia.proxy"))
		if err != nil {
			util.LogError("Could not set proxy for gophercloud client: %s .\n%s", proxyURL, err.Error())
		} else {
			providerClient.HTTPClient.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}
	}

	return openstack.NewIdentityV3(providerClient, gophercloud.EndpointOpts{})
}

type keystoneToken struct {
	DomainScope  keystoneTokenThing         `json:"domain"`
	ProjectScope keystoneTokenThingInDomain `json:"project"`
	Roles        []keystoneTokenThing       `json:"roles"`
	User         keystoneTokenThingInDomain `json:"user"`
	Token        string
}

type keystoneTokenThing struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type keystoneTokenThingInDomain struct {
	keystoneTokenThing
	Domain keystoneTokenThing `json:"domain"`
}

func (t *keystoneToken) ToContext() policy.Context {
	c := policy.Context{
		Roles: make([]string, 0, len(t.Roles)),
		Auth: map[string]string{
			"user_id":             t.User.ID,
			"user_name":           t.User.Name,
			"user_domain_id":      t.User.Domain.ID,
			"user_domain_name":    t.User.Domain.Name,
			"domain_id":           t.DomainScope.ID,
			"domain_name":         t.DomainScope.Name,
			"project_id":          t.ProjectScope.ID,
			"project_name":        t.ProjectScope.Name,
			"project_domain_id":   t.ProjectScope.Domain.ID,
			"project_domain_name": t.ProjectScope.Domain.Name,
			"token":               t.Token,
		},
		Request: map[string]string{
			"user_id":    t.User.ID,
			"domain_id":  t.DomainScope.ID,
			"project_id": t.ProjectScope.ID,
		},
		Logger: util.LogDebug,
	}
	for key, value := range c.Auth {
		if value == "" {
			delete(c.Auth, key)
		}
	}
	for _, role := range t.Roles {
		c.Roles = append(c.Roles, role.Name)
	}

	return c
}

//refreshToken fetches a new Keystone keystone token for the service user. It is also used
//to fetch the initial token on startup.
func (d keystone) refreshToken() error {
	//NOTE: This function is very similar to v3auth() in
	//gophercloud/openstack/client.go, but with a few differences:
	//
	//1. thread-safe token renewal
	//2. proper support for cross-domain scoping

	util.LogDebug("renewing Keystone token...")

	d.TokenRenewalMutex.Lock()
	defer d.TokenRenewalMutex.Unlock()

	providerClient.TokenID = viper.GetString("keystone.token")

	//TODO: crashes with RegionName != ""
	eo := gophercloud.EndpointOpts{Region: ""}
	keystone, err := openstack.NewIdentityV3(providerClient, eo)
	if err != nil {
		return fmt.Errorf("cannot initialize Keystone client: %v", err)
	}

	util.LogDebug("Keystone URL: %s", keystone.Endpoint)

	result := tokens.Create(keystone, authOptionsFromConfig())
	token, err := result.ExtractToken()
	if err != nil {
		return fmt.Errorf("cannot read token: %v", err)
	}
	catalog, err := result.ExtractServiceCatalog()
	if err != nil {
		return fmt.Errorf("cannot read service catalog: %v", err)
	}

	// store token so that it is considered for next authentication attempt
	viper.Set("keystone.token", token.ID)
	providerClient.TokenID = token.ID
	// providerClient.ReauthFunc = d.refreshToken //TODO: exponential backoff necessary or already provided by gophercloud?
	providerClient.EndpointLocator = func(opts gophercloud.EndpointOpts) (string, error) {
		return openstack.V3EndpointURL(catalog, opts)
	}

	return nil
}

func authOptionsFromConfig() *tokens.AuthOptions {
	return &tokens.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		TokenID:          viper.GetString("keystone.token"),
		Username:         viper.GetString("keystone.username"),
		Password:         viper.GetString("keystone.password"),
		DomainName:       viper.GetString("keystone.user_domain_name"),
		AllowReauth:      true,
		Scope: tokens.Scope{
			ProjectName: viper.GetString("keystone.project_name"),
			DomainName:  viper.GetString("keystone.project_domain_name"),
		},
	}
}

// Authenticate authenticates a user using available authOptionsFromRequest (username+password or token)
// It returns a keystoneToken that can be used to extract user and scope information (e.g. names)
func (d keystone) Authenticate(authOpts *tokens.AuthOptions, serviceUser bool) (*policy.Context, error) {
	// authorize call
	client, err := d.keystoneClient(serviceUser)
	if err != nil {
		util.LogError(err.Error())
		return nil, err
	}

	//use a custom token struct instead of tokens.Token which is way incomplete
	var tokenData keystoneToken
	if authOpts.TokenID != "" {
		util.LogInfo("verifying token")
		response := tokens.Get(client, authOpts.TokenID)
		if response.Err != nil {
			//this includes 4xx responses, so after this point, we can be sure that the token is valid
			return nil, response.Err
		}
		err = response.ExtractInto(&tokenData)
		if err != nil {
			return nil, err
		}
	} else {
		util.LogInfo("authenticate %s%s with scope %s.", authOpts.Username, authOpts.UserID, authOpts.Scope)
		response := tokens.Create(client, authOpts)
		// ugly copy & paste because the base-type of CreateResult and GetResult is private
		if response.Err != nil {
			//this includes 4xx responses, so after this point, we can be sure that the token is valid
			util.LogInfo(response.Err.Error())
			return nil, response.Err
		}
		err = response.ExtractInto(&tokenData)
		if err != nil {
			return nil, err
		}
		tokenData.Token = response.Header.Get("X-Subject-Token")
	}

	context := tokenData.ToContext()
	return &context, nil
}

// AuthenticateRequest attempts to Authenticate a user using the request header contents
// The resulting policy context can be used to authorize the user
// If no supported authOptionsFromRequest could be found, the context is nil
// If the authOptionsFromRequest are invalid or the authentication provider has issues, an error is returned
func (d keystone) AuthenticateRequest(r *http.Request) (*policy.Context, error) {
	authOpts, err := authOptionsFromRequest(r)
	if err != nil {
		util.LogError(err.Error())
		return nil, err
	}

	context, err := d.Authenticate(authOpts, true)
	if err != nil {
		return nil, err
	}

	// write this to request header (compatible with databus23/keystone)
	r.Header.Set("X-User-Id", context.Auth["user_id"])
	r.Header.Set("X-User-Name", context.Auth["username"])
	r.Header.Set("X-User-Domain-Id", context.Auth["user_domain_id"])
	r.Header.Set("X-User-Domain-Name", context.Auth["user_domain_name"])
	if context.Auth["project_id"] != "" {
		r.Header.Set("X-Project-Id", context.Auth["project_id"])
		r.Header.Set("X-Project-Name", context.Auth["project_name"])
		r.Header.Set("X-Project-Domain-Id", context.Auth["project_domain_id"])
		r.Header.Set("X-Project-Domain-Name", context.Auth["project_domain_name"])
	} else {
		r.Header.Set("X-Domain-Id", context.Auth["domain_id"])
		r.Header.Set("X-Domain-Name", context.Auth["domain_name"])
	}
	for _, role := range context.Roles {
		r.Header.Add("X-Roles", role)
	}

	return context, nil
}

// authOptionsFromRequest retrieves authOptionsFromRequest from http request and puts them into an AuthOptions structure
// It requires username to contain a qualified OpenStack username and project/domain scope information
// Format: <user>"|"<project> or <user>"|@"<domain>
// user/project can either be a unique OpenStack ID or a qualified name with domain information, e.g. username"@"domain
func authOptionsFromRequest(r *http.Request) (*tokens.AuthOptions, error) {
	ba := tokens.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		AllowReauth:      true,
	}

	username, password, ok := r.BasicAuth()
	if ok {
		usernameParts := strings.Split(username, "|")
		if len(usernameParts) != 2 {
			util.LogError("Insufficient parameters for basic authentication. Provide user|project or user|@domain and password")
			return nil, errors.New("Insufficient parameters for basic authentication. Provide user|project or user|@domain and password")
		}

		userParts := strings.Split(usernameParts[0], "@")
		scopeParts := strings.Split(usernameParts[1], "@")

		// parse username part
		if len(userParts) > 1 {
			ba.Username = userParts[0]
			ba.DomainName = userParts[1]
		} else {
			ba.UserID = userParts[0]
		}
		// parse scope part
		if len(scopeParts) > 1 {
			if scopeParts[0] != "" {
				ba.Scope.ProjectName = scopeParts[0]
			}
			ba.Scope.DomainName = scopeParts[1]
		} else {
			ba.Scope.ProjectID = scopeParts[0]
		}

		// set password
		ba.Password = password

		return &ba, nil
	} else if token := r.Header.Get("X-Auth-Token"); token != "" {
		ba.TokenID = token

		return &ba, nil
	} else {
		return nil, errors.New("Authorization header missing")
	}
}
