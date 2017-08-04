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
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"math"
	"math/rand"
	"strings"
	"time"
)

// Keystone creates a real keystone authentication and authorization driver
func Keystone() Driver {
	ks := keystone{}
	ks.tokenCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)
	ks.projectTreeCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)
	ks.mutex = &sync.Mutex{}

	if viper.Get("keystone.username") != nil {
		ks.keystoneClient(true)
		ks.reauthServiceUser()
	}

	return &ks
}

type keystone struct {
	mutex                        *sync.Mutex
	tokenCache, projectTreeCache *cache.Cache
	providerClient               *gophercloud.ServiceClient
	seqErrors                    int
	serviceURL                   string
}

func (d *keystone) keystoneClient(asServiceUser bool) (*gophercloud.ServiceClient, error) {

	if asServiceUser {
		d.mutex.Lock()
		defer d.mutex.Unlock()

		var err error
		if d.providerClient == nil {
			util.LogInfo("Setting up identity connection to %s", viper.GetString("keystone.auth_url"))
			d.providerClient, err = newKeystoneClient()
		}
		return d.providerClient, err
	}

	return newKeystoneClient()
}

func newKeystoneClient() (*gophercloud.ServiceClient, error) {
	provider, err := openstack.NewClient(viper.GetString("keystone.auth_url"))
	if viper.IsSet("maia.proxy") {
		proxyURL, err := url.Parse(viper.GetString("maia.proxy"))
		if err != nil {
			util.LogError("Could not set proxy for gophercloud client: %s .\n%s", proxyURL, err.Error())
		} else {
			provider.HTTPClient.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}
	}
	client, err := openstack.NewIdentityV3(provider, gophercloud.EndpointOpts{
		Region: "",
	})
	if err != nil {
		return nil, fmt.Errorf("cannot initialize OpenStack client: %v", err)
	}

	return client, nil
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

type cacheEntry struct {
	context     *policy.Context
	endpointURL string
	projectTree []string
}

// ServiceURL returns the service's global catalog entry
// The result is empty when called from a client
func (d *keystone) ServiceURL() string {
	return d.serviceURL
}

// reauthServiceUser refreshes an expired keystone token
func (d *keystone) reauthServiceUser() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	authOpts := authOptionsFromConfig()
	util.LogInfo("Fetching token for service user %s%s@%s%s", authOpts.UserID, authOpts.Username, authOpts.DomainID, authOpts.DomainName)

	result := tokens.Create(d.providerClient, authOpts)
	token, err := result.ExtractToken()
	if err != nil {
		// wait ~ (2^errors)/2, i.e. 0..1, 0..2, 0..4, ... increasing with every sequential error
		r := rand.Intn(int(math.Exp2(float64(d.seqErrors))))
		time.Sleep(time.Duration(r) * time.Second)
		d.seqErrors++
		return fmt.Errorf("Cannot obtain token: %v (%d sequential errors)", err, d.seqErrors)
	}
	catalog, err := result.ExtractServiceCatalog()

	if err != nil {
		return fmt.Errorf("cannot read service catalog: %v", err)
	}
	d.serviceURL, err = openstack.V3EndpointURL(catalog, gophercloud.EndpointOpts{Type: "metrics", Availability: gophercloud.AvailabilityPublic})

	// store token so that it is considered for next authentication attempt
	viper.Set("keystone.token", token.ID)
	d.providerClient.TokenID = token.ID
	d.providerClient.ReauthFunc = d.reauthServiceUser
	d.providerClient.EndpointLocator = func(opts gophercloud.EndpointOpts) (string, error) {
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

func authOpts2StringKey(authOpts *tokens.AuthOptions) string {
	if authOpts.TokenID != "" {
		return authOpts.TokenID + authOpts.Scope.ProjectID + " " + authOpts.Scope.ProjectName + " " +
			authOpts.Scope.DomainID + " " + authOpts.Scope.DomainName
	}

	// build unique key by separating fields with blanks. Since blanks are not allowed in several of those
	// the result will be unique
	return authOpts.UserID + " " + authOpts.Username + " " + authOpts.Password + " " + authOpts.DomainID + " " +
		authOpts.DomainName + " " + authOpts.Scope.ProjectID + " " + authOpts.Scope.ProjectName + " " +
		authOpts.Scope.DomainID + " " + authOpts.Scope.DomainName
}

// Authenticate authenticates a non-service user using available authOptionsFromRequest (username+password or token)
// It returns the authorization context
func (d *keystone) Authenticate(authOpts *tokens.AuthOptions) (*policy.Context, string, error) {
	return d.authenticate(authOpts, false)
}

// authenticate authenticates a user using available authOptionsFromRequest (username+password or token)
// It returns the authorization context
func (d *keystone) authenticate(authOpts *tokens.AuthOptions, asServiceUser bool) (*policy.Context, string, error) {
	// check cache briefly
	if entry, found := d.tokenCache.Get(authOpts2StringKey(authOpts)); found {
		util.LogDebug("Token cache hit for %s", authOpts.TokenID)
		return entry.(*cacheEntry).context, entry.(*cacheEntry).endpointURL, nil
	}

	// get identity connection
	client, err := d.keystoneClient(asServiceUser)
	if err != nil {
		util.LogError(err.Error())
		return nil, "", err
	}

	// authenticate service user
	if asServiceUser {
		// need an authenticated service user to check tokens and build the project tree
		if client.TokenID == "" {
			d.reauthServiceUser()
		}
	}

	//use a custom token struct instead of tokens.Token which is way incomplete
	var tokenData keystoneToken
	var catalog *tokens.ServiceCatalog
	if authOpts.TokenID != "" && asServiceUser {
		util.LogDebug("verifying token")
		// get token from token-ID which is being verified on that occasion
		response := tokens.Get(client, authOpts.TokenID)
		if response.Err != nil {
			//this includes 4xx responses, so after this point, we can be sure that the token is valid
			return nil, "", response.Err
		}
		err = response.ExtractInto(&tokenData)
		if err != nil {
			return nil, "", err
		}
		catalog, err = response.ExtractServiceCatalog()
		if err != nil {
			return nil, "", err
		}
	} else {
		util.LogDebug("authenticate %s%s with scope %s.", authOpts.Username, authOpts.UserID, authOpts.Scope)
		// create new token from basic authentication credentials or token ID
		response := tokens.Create(client, authOpts)
		// ugly copy & paste because the base-type of CreateResult and GetResult is private
		if response.Err != nil {
			//this includes 4xx responses, so after this point, we can be sure that the token is valid
			if authOpts.Username != "" || authOpts.UserID != "" {
				util.LogInfo("Failed login of user %s%s for scope %s: %s", authOpts.Username, authOpts.UserID, authOpts.Scope, response.Err.Error())
			} else {
				util.LogInfo("Failed login of with token %s ... for scope %s: %s", authOpts.TokenID[:1+len(authOpts.TokenID)/4], authOpts.Scope, response.Err.Error())
			}
			return nil, "", response.Err
		}
		err = response.ExtractInto(&tokenData)
		if err != nil {
			return nil, "", err
		}
		catalog, err = response.ExtractServiceCatalog()
		if err != nil {
			return nil, "", err
		}
		// the token is passed separately
		tokenData.Token = response.Header.Get("X-Subject-Token")
	}

	// authorization context
	context := tokenData.ToContext()
	// project tree (children)
	projectID := tokenData.ProjectScope.ID
	if asServiceUser && projectID != "" {
		d.updateProjectTree(client, projectID)
	}
	// service endpoint
	endpointURL, err := openstack.V3EndpointURL(catalog, gophercloud.EndpointOpts{Type: "metrics", Availability: gophercloud.AvailabilityPublic})

	// update the cache
	ce := cacheEntry{
		context:     &context,
		endpointURL: endpointURL,
	}
	d.tokenCache.Set(authOpts2StringKey(authOpts), &ce, cache.DefaultExpiration)
	return &context, endpointURL, nil
}

func (d *keystone) ChildProjects(projectID string) []string {
	if ce, ok := d.projectTreeCache.Get(projectID); ok {
		return ce.([]string)
	}

	return []string{}
}

func (d *keystone) updateProjectTree(client *gophercloud.ServiceClient, projectID string) {

	d.mutex.Lock()
	defer d.mutex.Unlock()

	childProjectIDs, err := childProjects(client, projectID)
	if err != nil {
		util.LogError("Unable to obtain project tree of project %s: %v", projectID, err)
	}
	d.projectTreeCache.Set(projectID, childProjectIDs, cache.DefaultExpiration)
}

func childProjects(client *gophercloud.ServiceClient, projectID string) ([]string, error) {
	enabledVal := true
	list, err := projects.List(client, projects.ListOpts{ParentID: projectID, Enabled: &enabledVal}).AllPages()
	if err != nil {
		return nil, err
	}
	slice, err := projects.ExtractProjects(list)
	if err != nil {
		return nil, err
	}
	projectIDs := []string{}
	for _, p := range slice {
		projectIDs = append(projectIDs, p.ID)
		children, err := childProjects(client, p.ID)
		if err != nil {
			return nil, err
		}
		projectIDs = append(projectIDs, children...)
	}
	return projectIDs, nil
}

// AuthenticateRequest attempts to Authenticate a user using the request header contents
// The resulting policy context can be used to authorize the user
// If no supported authOptionsFromRequest could be found, the context is nil
// If the authOptionsFromRequest are invalid or the authentication provider has issues, an error is returned
func (d *keystone) AuthenticateRequest(r *http.Request) (*policy.Context, error) {
	authOpts, err := authOptionsFromRequest(r)
	if err != nil {
		util.LogError(err.Error())
		return nil, err
	}

	// if the request does not have a keystone token, then a new token has to be requested on behalf of the client
	// this must not happen with the connection of the service otherwise wrong credentials will cause reauthentication
	// of the service user
	hasToken := authOpts.TokenID != ""
	context, _, err := d.authenticate(authOpts, hasToken)
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
	if r.Header.Get("X-Auth-Token") == "" {
		r.Header.Set("X-Auth-Token", context.Auth["token"])
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
		AllowReauth:      false,
	}

	if token := r.Header.Get("X-Auth-Token"); token != "" {
		ba.TokenID = token

		return &ba, nil
	} else if cookie, err := r.Cookie("X-Auth-Token"); err == nil {
		ba.TokenID = cookie.Value

		return &ba, nil
	} else if username, password, ok := r.BasicAuth(); ok {
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
	}

	return nil, errors.New("Authorization header missing")
}
