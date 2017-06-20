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

	policy "github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/pkg/errors"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
)

// Keystone creates a real keystone authentication and authorization driver
func Keystone() Driver {
	return keystone{}
}

type keystone struct {
	TokenRenewalMutex *sync.Mutex
}

var providerClient *gophercloud.ProviderClient
var domainNameCache *map[string]string
var projectNameCache *map[string]string
var userNameCache *map[string]string
var userIDCache *map[string]string

func (d keystone) keystoneClient(iServiceUser bool) (*gophercloud.ServiceClient, error) {
	if d.TokenRenewalMutex == nil {
		d.TokenRenewalMutex = &sync.Mutex{}
	}
	if domainNameCache == nil {
		domainNameCache = &map[string]string{}
	}
	if projectNameCache == nil {
		projectNameCache = &map[string]string{}
	}
	if userNameCache == nil {
		userNameCache = &map[string]string{}
	}
	if userIDCache == nil {
		userIDCache = &map[string]string{}
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
func (d keystone) ListDomains() ([]Domain, error) {
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
		Domains []Domain `json:"domains"`
	}
	err = result.ExtractInto(&data)
	return data.Domains, err
}

//ListProjects implements the Driver interface.
func (d keystone) ListProjects() ([]Project, error) {
	client, err := d.keystoneClient(true)
	if err != nil {
		return nil, err
	}

	var result gophercloud.Result
	_, err = client.Get("/v3/keystone/projects", &result.Body, nil)
	if err != nil {
		return nil, err
	}

	var data struct {
		Projects []Project `json:"projects"`
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
		Domain Domain `json:"domain"`
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
		Project Project `json:"project"`
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
		User User `json:"user"`
	}
	err = result.ExtractInto(&data)
	if err == nil {
		(*userNameCache)[id] = data.User.Name
		(*userIDCache)[data.User.Name] = id
	}
	return data.User.Name, err
}

func (d keystone) UserID(name string) (string, error) {
	cachedID, hit := (*userIDCache)[name]
	if hit {
		return cachedID, nil
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
		User []User `json:"user"`
	}
	err = result.ExtractInto(&data)
	userID := ""
	if err == nil {
		switch len(data.User) {
		case 0:
			err = errors.Errorf("No user found with name %s", name)
		case 1:
			userID = data.User[0].UUID
		default:
			util.LogWarning("Multiple users found with name %s - returning the first one", name)
			userID = data.User[0].UUID
		}
		(*userIDCache)[name] = userID
		(*userNameCache)[userID] = name
	}
	return userID, err
}

type keystoneToken struct {
	DomainScope  keystoneTokenThing         `json:"domain"`
	ProjectScope keystoneTokenThingInDomain `json:"project"`
	Roles        []keystoneTokenThing       `json:"roles"`
	User         keystoneTokenThingInDomain `json:"user"`
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
			"tenant_id":           t.ProjectScope.ID,
			"tenant_name":         t.ProjectScope.Name,
			"tenant_domain_id":    t.ProjectScope.Domain.ID,
			"tenant_domain_name":  t.ProjectScope.Domain.Name,
		},
		Request: nil,
		Logger:  util.LogDebug,
	}
	for key, value := range c.Auth {
		if value == "" {
			delete(c.Auth, key)
		}
	}
	for _, role := range t.Roles {
		c.Roles = append(c.Roles, role.Name)
	}
	if c.Request == nil {
		c.Request = map[string]string{}
	}

	return c
}

//RefreshToken fetches a new Keystone keystone token. It is also used
//to fetch the initial token on startup.
func (d keystone) RefreshToken() error {
	//NOTE: This function is very similar to v3auth() in
	//gophercloud/openstack/client.go, but with a few differences:
	//
	//1. thread-safe token renewal
	//2. proper support for cross-domain scoping

	util.LogDebug("renewing Keystone token...")

	d.TokenRenewalMutex.Lock()
	defer d.TokenRenewalMutex.Unlock()

	providerClient.TokenID = ""

	//TODO: crashes with RegionName != ""
	eo := gophercloud.EndpointOpts{Region: ""}
	keystone, err := openstack.NewIdentityV3(providerClient, eo)
	if err != nil {
		return fmt.Errorf("cannot initialize Keystone client: %v", err)
	}

	util.LogDebug("Keystone URL: %s", keystone.Endpoint)

	result := tokens.Create(keystone, d.AuthOptionsFromConfig())
	token, err := result.ExtractToken()
	if err != nil {
		return fmt.Errorf("cannot read token: %v", err)
	}
	catalog, err := result.ExtractServiceCatalog()
	if err != nil {
		return fmt.Errorf("cannot read service catalog: %v", err)
	}

	providerClient.TokenID = token.ID
	providerClient.ReauthFunc = d.RefreshToken //TODO: exponential backoff necessary or already provided by gophercloud?
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

func (d keystone) AuthOptionsFromBasicAuthCredentials(userID string, password string, tenantID string) *gophercloud.AuthOptions {
	return &gophercloud.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		UserID:           userID,
		Password:         password,
		// Note: gophercloud only allows for user & project in the same domain
		TenantID: tenantID,
	}
}

func (d keystone) AuthOptionsFromConfig() *gophercloud.AuthOptions {
	return &gophercloud.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		Username:         viper.GetString("keystone.username"),
		Password:         viper.GetString("keystone.password"),
		DomainName:       viper.GetString("keystone.user_domain_name"),
		// Note: gophercloud only allows for user & project in the same domain
		TenantName: viper.GetString("keystone.project_name"),
	}
}
