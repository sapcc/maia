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
			err = d.RefreshToken()
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

func (d keystone) Client() *gophercloud.ProviderClient {
	var kc keystone

	err := viper.UnmarshalKey("keystone", &kc)
	if err != nil {
		util.LogError("unable to decode into struct, %v", err)
	}

	return nil
}

//ListDomains implements the Driver interface.
func (d keystone) ListDomains() ([]KeystoneDomain, error) {
	client, err := d.keystoneClient(true)
	if err != nil {
		return nil, err
	}

	//gophercloud does not support domain listing yet - do it manually
	url := client.ServiceURL("domains")
	var result gophercloud.Result
	_, err = client.Get(url, &result.Body, nil)
	if err != nil {
		return nil, err
	}

	var data struct {
		Domains []KeystoneDomain `json:"domains"`
	}
	err = result.ExtractInto(&data)
	return data.Domains, err
}

//ListProjects implements the Driver interface.
func (d keystone) ListProjects() ([]KeystoneProject, error) {
	client, err := d.keystoneClient(true)
	if err != nil {
		return nil, err
	}

	var result gophercloud.Result
	_, err = client.Get("/v3/auth/projects", &result.Body, nil)
	if err != nil {
		return nil, err
	}

	var data struct {
		Projects []KeystoneProject `json:"projects"`
	}
	err = result.ExtractInto(&data)
	return data.Projects, err
}

func (d keystone) ValidateToken(token string) (policy.Context, error) {
	client, err := d.keystoneClient(true)
	if err != nil {
		return policy.Context{}, err
	}

	response := tokens.Get(client, token)
	if response.Err != nil {
		//this includes 4xx responses, so after this point, we can be sure that the token is valid
		return policy.Context{}, response.Err
	}

	//use a custom token struct instead of tokens.Token which is way incomplete
	var tokenData keystoneToken
	err = response.ExtractInto(&tokenData)
	if err != nil {
		return policy.Context{}, err
	}
	return tokenData.ToContext(), nil
}

func (d keystone) Authenticate(credentials *gophercloud.AuthOptions) (policy.Context, error) {
	client, err := d.keystoneClient(true)
	if err != nil {
		return policy.Context{}, err
	}
	response := tokens.Create(client, credentials)
	if response.Err != nil {
		//this includes 4xx responses, so after this point, we can be sure that the token is valid
		return policy.Context{}, response.Err
	}
	//use a custom token struct instead of tokens.Token which is way incomplete
	var tokenData keystoneToken
	err = response.ExtractInto(&tokenData)
	if err != nil {
		return policy.Context{}, err
	}
	return tokenData.ToContext(), nil
}

func (d keystone) AuthenticateUser(credentials *gophercloud.AuthOptions) (policy.Context, error) {
	client, err := d.keystoneClient(false)
	if err != nil {
		return policy.Context{}, err
	}
	response := tokens.Create(client, credentials)
	if response.Err != nil {
		//this includes 4xx responses, so after this point, we can be sure that the token is valid
		return policy.Context{}, response.Err
	}
	//use a custom token struct instead of tokens.Token which is way incomplete
	var tokenData keystoneToken
	err = response.ExtractInto(&tokenData)
	if err != nil {
		return policy.Context{}, err
	}
	return tokenData.ToContext(), nil
}

func (d keystone) DomainName(id string) (string, error) {
	cachedName, hit := (*domainNameCache)[id]
	if hit {
		return cachedName, nil
	}

	client, err := d.keystoneClient(true)
	if err != nil {
		return "", err
	}

	var result gophercloud.Result
	url := client.ServiceURL(fmt.Sprintf("domains/%s", id))
	_, err = client.Get(url, &result.Body, nil)
	if err != nil {
		return "", err
	}

	var data struct {
		Domain KeystoneDomain `json:"domain"`
	}
	err = result.ExtractInto(&data)
	if err == nil {
		(*domainNameCache)[id] = data.Domain.Name
	}
	return data.Domain.Name, err
}

func (d keystone) ProjectName(id string) (string, error) {
	cachedName, hit := (*projectNameCache)[id]
	if hit {
		return cachedName, nil
	}

	client, err := d.keystoneClient(true)
	if err != nil {
		return "", err
	}

	var result gophercloud.Result
	url := client.ServiceURL(fmt.Sprintf("projects/%s", id))
	_, err = client.Get(url, &result.Body, nil)
	if err != nil {
		return "", err
	}

	var data struct {
		Project KeystoneProject `json:"project"`
	}
	err = result.ExtractInto(&data)
	if err == nil {
		(*projectNameCache)[id] = data.Project.Name
	}
	return data.Project.Name, err
}

func (d keystone) UserName(id string) (string, error) {
	cachedName, hit := (*userNameCache)[id]
	if hit {
		return cachedName, nil
	}

	client, err := d.keystoneClient(true)
	if err != nil {
		return "", err
	}

	var result gophercloud.Result
	url := client.ServiceURL(fmt.Sprintf("users/%s", id))
	_, err = client.Get(url, &result.Body, nil)
	if err != nil {
		return "", err
	}

	var data struct {
		User KeystoneUser `json:"user"`
	}
	err = result.ExtractInto(&data)
	if err == nil {
		(*userNameCache)[id] = data.User.Name
		(*userIdCache)[data.User.Name] = id
	}
	return data.User.Name, err
}

func (d keystone) UserId(name string) (string, error) {
	cachedId, hit := (*userIdCache)[name]
	if hit {
		return cachedId, nil
	}

	client, err := d.keystoneClient(true)
	if err != nil {
		return "", err
	}

	var result gophercloud.Result
	url := client.ServiceURL(fmt.Sprintf("users?name=%s", name))
	_, err = client.Get(url, &result.Body, nil)
	if err != nil {
		return "", err
	}

	var data struct {
		User []KeystoneUser `json:"user"`
	}
	err = result.ExtractInto(&data)
	userId := ""
	if err == nil {
		switch len(data.User) {
		case 0:
			err = errors.Errorf("No user found with name %s", name)
		case 1:
			userId = data.User[0].UUID
		default:
			util.LogWarning("Multiple users found with name %s - returning the first one", name)
			userId = data.User[0].UUID
		}
		(*userIdCache)[name] = userId
		(*userNameCache)[userId] = name
	}
	return userId, err
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

func (d keystone) AuthOptionsFromBasicAuthToken(tokenID string) *gophercloud.AuthOptions {
	return &gophercloud.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		TokenID:          tokenID,
	}
}

func (d keystone) AuthOptionsFromBasicAuthCredentials(userID string, password string, projectId string) *gophercloud.AuthOptions {
	return &gophercloud.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		UserID:           userID,
		Password:         password,
		// Note: gophercloud only allows for user & project in the same domain
		TenantID: projectId,
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
