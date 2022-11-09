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

	"regexp"
	"strings"
	"time"

	policy "github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/users"
	"github.com/gophercloud/gophercloud/pagination"
	cache "github.com/patrickmn/go-cache"
	"github.com/spf13/viper"

	"github.com/sapcc/maia/pkg/util"
)

var metricsEndpointOpts = gophercloud.EndpointOpts{Type: "metrics", Availability: gophercloud.AvailabilityPublic}

// Keystone creates a real keystone authentication and authorization driver
func Keystone() Driver {
	ks := keystone{}
	ks.init()

	return &ks
}

type keystone struct {
	// these locks are used to make sure the connection or token is not altered while somebody is working on it
	serviceConnMutex, serviceTokenMutex *sync.Mutex
	// these caches are thread-safe, no need to lock because worst-case is duplicate processing efforts
	tokenCache, projectTreeCache, userProjectsCache, userIDCache, projectScopeCache *cache.Cache
	providerClient                                                                  *gophercloud.ServiceClient
	serviceURL                                                                      string
	// role-id --> role-name
	monitoringRoles map[string]string
	// domain-id --> domain-name
	domainNames map[string]string
	// domain-name --> domain-id
	domainIDs map[string]string
}

func (d *keystone) init() {
	d.tokenCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)
	d.projectTreeCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)
	d.userProjectsCache = cache.New(viper.GetDuration("keystone.token_cache_time"), time.Minute)
	d.userIDCache = cache.New(time.Hour*24, time.Hour)
	d.projectScopeCache = cache.New(time.Hour*24, time.Hour)
	d.serviceConnMutex = &sync.Mutex{}
	d.serviceTokenMutex = &sync.Mutex{}
	if viper.Get("keystone.username") != nil {
		// force service logon to check validity early
		// this will set d.providerClient
		_, err := d.serviceKeystoneClient()
		if err != nil {
			panic(err)
		}
	}
}

// serviceKeystoneClient creates and returns the keystone connection used by the running service
func (d *keystone) serviceKeystoneClient() (*gophercloud.ServiceClient, error) {
	d.serviceConnMutex.Lock()
	defer d.serviceConnMutex.Unlock()

	if d.providerClient == nil {
		util.LogInfo("Setting up identity connection to %s", viper.GetString("keystone.auth_url"))
		client, err := newKeystoneClient(authOptionsFromConfig())
		if err != nil {
			return nil, err
		}
		d.providerClient = client
		// load the list of all known domains and roles to avoid frequent API calls
		// changes will not be recognized at runtime
		d.loadDomainsAndRoles()
	}

	return d.providerClient, nil
}

// newKeystoneClient creates a new keystone-connection
func newKeystoneClient(authOpts gophercloud.AuthOptions) (*gophercloud.ServiceClient, error) {
	provider, err := openstack.AuthenticatedClient(authOpts)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize OpenStack service user provider client: %v", err)
	}
	if viper.IsSet("maia.proxy") {
		proxyURL, err := url.Parse(viper.GetString("maia.proxy"))
		if err != nil {
			util.LogError("Could not set proxy for gophercloud client: %s .\n%s", proxyURL, err.Error())
			return nil, err
		}
		provider.HTTPClient.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}
	client, err := openstack.NewIdentityV3(provider, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("cannot initialize OpenStack service user identity V3 client: %v", err)
	}

	return client, nil
}

// keystoneToken combines all parts of a get-token result into a single struct.
// It is a replacement for the somewhat annoying need to call
// various Extract...() methods on a GetResult to collect all
// the bits and pieces
type keystoneToken struct {
	DomainScope  keystoneTokenThing         `json:"domain"`
	ProjectScope keystoneTokenThingInDomain `json:"project"`
	Roles        []keystoneTokenThing       `json:"roles"`
	User         keystoneTokenThingInDomain `json:"user"`
	Application  keystoneTokenThingInDomain `json:"application"`
	Token        string
	ExpiresAt    string `json:"expires_at"`
}

// keystoneTokenThing is an OpenStack resource identifier
type keystoneTokenThing struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// keystoneTokenThingInDomain is a qualified resource identifier
type keystoneTokenThingInDomain struct {
	keystoneTokenThing
	Domain keystoneTokenThing `json:"domain"`
}

// ToContext transforms our custom keystoneToken structure
// into a databus23 policy context
func (t *keystoneToken) ToContext() policy.Context {
	c := policy.Context{
		Roles: make([]string, 0, len(t.Roles)),
		Auth: map[string]string{
			"user_id":                     t.User.ID,
			"user_name":                   t.User.Name,
			"user_domain_id":              t.User.Domain.ID,
			"user_domain_name":            t.User.Domain.Name,
			"application_credential_id":   t.Application.ID,
			"application_credential_name": t.Application.Name,
			"domain_id":                   t.DomainScope.ID,
			"domain_name":                 t.DomainScope.Name,
			"project_id":                  t.ProjectScope.ID,
			"project_name":                t.ProjectScope.Name,
			"project_domain_id":           t.ProjectScope.Domain.ID,
			"project_domain_name":         t.ProjectScope.Domain.Name,
			"token":                       t.Token,
			"token-expiry":                t.ExpiresAt,
		},
		Request: map[string]string{
			"user_id":                     t.User.ID,
			"domain_id":                   t.DomainScope.ID,
			"project_id":                  t.ProjectScope.ID,
			"application_credential_id":   t.Application.ID,
			"application_credential_name": t.Application.Name,
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

// cacheEntry contains the result of a get-token call to Keystone
// so instead of a call to Keystone the cache can be consulted
type cacheEntry struct {
	context     *policy.Context
	endpointURL string
}

// ServiceURL returns the service's global catalog entry
// The result is empty when called from a client
func (d *keystone) ServiceURL() string {
	return d.serviceURL
}

// loadDomainsAndRoles builds an "index" for roles and domains
// to avoid frequent calls to Keystone
func (d *keystone) loadDomainsAndRoles() {
	util.LogInfo("Loading/refreshing global list of domains and roles")

	allRoles := struct {
		Roles []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"roles"`
	}{}

	u := d.providerClient.ServiceURL("roles")
	resp, err := d.providerClient.Get(u, &allRoles, nil)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// get list of all monitoring role names
	rolesNames := strings.Split(viper.GetString("keystone.roles"), ",")

	d.monitoringRoles = map[string]string{}
	// get all known roles and match them with our own list to get the ID
	for _, ar := range allRoles.Roles {
		for _, name := range rolesNames {
			matched, err := regexp.MatchString(name, ar.Name)
			if err != nil {
				panic(err)
			}
			if matched {
				d.monitoringRoles[ar.ID] = name
				break
			}
		}
	}

	// load domains
	d.domainNames = map[string]string{}
	d.domainIDs = map[string]string{}
	trueVal := true
	err = projects.List(d.providerClient, projects.ListOpts{IsDomain: &trueVal, Enabled: &trueVal}).EachPage(func(page pagination.Page) (bool, error) {
		domains, err := projects.ExtractProjects(page)
		if err != nil {
			panic(err)
		}
		for _, domain := range domains {
			d.domainNames[domain.ID] = domain.Name
			d.domainIDs[domain.Name] = domain.ID
		}
		return true, nil
	})
	if err != nil {
		panic(err)
	}
}

// authOptionsFromConfig builds the AuthOptions struct for the service user from the configuration
func authOptionsFromConfig() gophercloud.AuthOptions {
	return gophercloud.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		TokenID:          viper.GetString("keystone.token"),
		Username:         viper.GetString("keystone.username"),
		Password:         viper.GetString("keystone.password"),
		DomainName:       viper.GetString("keystone.user_domain_name"),
		AllowReauth:      true,
		Scope: &gophercloud.AuthScope{
			ProjectName: viper.GetString("keystone.project_name"),
			DomainName:  viper.GetString("keystone.project_domain_name"),
		},
	}
}

// authOpts2StringKey builds a key from an AuthOptions struct for use with the token cache
func authOpts2StringKey(authOpts gophercloud.AuthOptions) string {
	// the key of a token is the token itself
	if authOpts.TokenID != "" {
		return authOpts.TokenID
	}

	// build unique key by separating fields with blanks. Since blanks are not allowed in several of those
	// the result will be unique

	// for Application Credentials there will be no scope so it can't be used to store the token
	if authOpts.ApplicationCredentialID != "" || authOpts.ApplicationCredentialName != "" {
		return authOpts.UserID + " " + authOpts.Username + " " + authOpts.Password + " " + authOpts.DomainID + " " +
			authOpts.DomainName + " " + authOpts.ApplicationCredentialID + " " + authOpts.ApplicationCredentialName + " " +
			authOpts.ApplicationCredentialSecret
	}

	// for basic authentiation credentials we need to take into account the scoping information as well
	return authOpts.UserID + " " + authOpts.Username + " " + authOpts.Password + " " + authOpts.DomainID + " " +
		authOpts.DomainName + " " + authOpts.Scope.ProjectID + " " + authOpts.Scope.ProjectName + " " +
		authOpts.Scope.DomainID + " " + authOpts.Scope.DomainName
}

// Authenticate authenticates a non-service user using available authOptionsFromRequest (username+password or token)
// It returns the authorization context
func (d *keystone) Authenticate(authOpts gophercloud.AuthOptions) (*policy.Context, string, AuthenticationError) {
	return d.authenticate(authOpts, false, false)
}

// AuthenticateRequest attempts to Authenticate a user using the request header contents
// The resulting policy context can be used to authorize the user
// If no supported authOptionsFromRequest could be found, the context is nil
// If the authOptionsFromRequest are invalid or the authentication provider has issues, an error is returned
// When guessScope is set to true, the method will try to find a suitible project when the scope is not defined (basic auth. only)
func (d *keystone) AuthenticateRequest(r *http.Request, guessScope bool) (*policy.Context, AuthenticationError) {
	authOpts, err := d.authOptionsFromRequest(r, guessScope)
	if err != nil {
		util.LogError(err.Error())
		return nil, err
	}

	// if the request does not have a keystone token, then a new token has to be requested on behalf of the client
	// this must not happen with the connection of the service otherwise wrong credentials will cause reauthentication
	// of the service user
	context, _, err := d.authenticate(*authOpts, true, false)
	if err != nil {
		return nil, err
	}

	// the resulting policy Context structure is copied into header fields
	// so that we do not have to add an extra parameter to every function.
	r.Header.Set("X-User-Id", context.Auth["user_id"])
	r.Header.Set("X-User-Name", context.Auth["user_name"])
	r.Header.Set("X-User-Domain-Id", context.Auth["user_domain_id"])
	r.Header.Set("X-User-Domain-Name", context.Auth["user_domain_name"])
	r.Header.Set("X-Application-Credential-Id", context.Auth["application_credential_id"])
	r.Header.Set("X-Application-Credential-Name", context.Auth["application_credential_name"])
	r.Header.Set("X-Application-Credential-Secret", context.Auth["application_credential_secret"])

	if context.Auth["project_id"] != "" {
		// user is scoped to project
		r.Header.Set("X-Project-Id", context.Auth["project_id"])
		r.Header.Set("X-Project-Name", context.Auth["project_name"])
		r.Header.Set("X-Project-Domain-Id", context.Auth["project_domain_id"])
		r.Header.Set("X-Project-Domain-Name", context.Auth["project_domain_name"])
	} else {
		// user is scoped to domain
		r.Header.Set("X-Domain-Id", context.Auth["domain_id"])
		r.Header.Set("X-Domain-Name", context.Auth["domain_name"])
	}
	// add each role as well (Add will queue up the items passed in)
	for _, role := range context.Roles {
		r.Header.Add("X-Roles", role)
	}
	r.Header.Set("X-Auth-Token", context.Auth["token"])
	r.Header.Set("X-Auth-Token-Expiry", context.Auth["token-expiry"])

	return context, nil
}

// authOptionsFromRequest retrieves authOptionsFromRequest from http request and puts them into an AuthOptions structure
// It requires username to contain a qualified OpenStack username and project/domain scope information
// Format: <user>"|"<project> or <user>"|@"<domain>
// user/project can either be a unique OpenStack ID or a qualified name with domain information, e.g. username"@"domain
// When guessScope is set to true, the method will try to find a suitible project when the scope is not defined (basic auth. only)
// Finally you can also specify the scope as URL query param
func (d *keystone) authOptionsFromRequest(r *http.Request, guessScope bool) (*gophercloud.AuthOptions, AuthenticationError) {
	ba := gophercloud.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		AllowReauth:      true,
	}

	// Get application credentials from header
	appCredID := r.Header.Get("X-Application-Credential-Id")
	appCredSecret := r.Header.Get("X-Application-Credential-Secret")
	appCredName := r.Header.Get("X-Application-Credential-Name")
	appCredUserName := r.Header.Get("X-User-Name")

	// extract credentials
	query := r.URL.Query()
	if token := r.Header.Get("X-Auth-Token"); token != "" {
		// perfect: we have a token and thus a authorization scope
		ba.TokenID = token
	} else if token := query.Get("x-auth-token"); token != "" {
		// perfect: we have a token and thus a authorization scope (albeit in lower-case)
		ba.TokenID = token
		// move to right place
		query.Del("x-auth-token")
		r.Header.Set("X-Auth-Token", ba.TokenID)
	} else if (appCredID != "" && appCredSecret != "") || (appCredName != "" && appCredUserName != "") {
		ba.ApplicationCredentialID = appCredID
		ba.ApplicationCredentialName = appCredName
		ba.ApplicationCredentialSecret = appCredSecret
		return &ba, nil
	} else if username, password, ok := r.BasicAuth(); ok {
		// use our own flavour of basic auth. where the username is used for scoping or application credentials, too
		isAppCred := strings.HasPrefix(username, "*")
		usernameParts := strings.Split(username, "|")
		userParts := strings.Split(usernameParts[0], "@")
		var scopeParts []string
		if len(usernameParts) > 1 {
			scopeParts = strings.Split(strings.Join(usernameParts[1:], "|"), "@")
		} else {
			// default to arbitrary project with sufficient roles after knowing the user
			scopeParts = []string{}
		}

		// handle application credentials
		if isAppCred {
			// if the username is prefixed with '*', we assume these are application credentials
			if len(userParts) == 1 {
				// this is application credential ID (remove the leading '*')
				ba.ApplicationCredentialID = userParts[0][1:]
			} else if len(userParts) >= 2 {
				// this is an application credential name qualified with a username
				ba.ApplicationCredentialName = userParts[0][1:]
				if len(userParts) > 2 {
					// the username is qualified, too
					ba.Username = userParts[1]
					ba.DomainName = strings.Join(userParts[2:], "@")
				} else if headerUserDomain := r.Header.Get("X-User-Domain-Name"); headerUserDomain != "" {
					// if the domain is set in the header, an unqualified username is taken as a name and not an ID
					ba.Username = userParts[1]
					ba.DomainName = headerUserDomain
				} else {
					// guess this is an ID
					ba.UserID = userParts[1]
				}
			}
			ba.ApplicationCredentialSecret = password

			return &ba, nil
		}

		// proceed with username password authentication
		if len(userParts) > 1 {
			// username@user-domain-name
			ba.Username = userParts[0]
			ba.DomainName = strings.Join(userParts[1:], "@")
		} else if headerUserDomain := r.Header.Get("X-User-Domain-Name"); headerUserDomain != "" {
			// if the domain is set in the header, an unqualified username is taken as a name and not an ID
			ba.Username = userParts[0]
			ba.DomainName = headerUserDomain
		} else {
			// idea: guess if this is a name of an ID
			ba.UserID = userParts[0]
		}

		// check if the scope is defined by qualified project name or by unique project ID
		if len(scopeParts) >= 2 {
			// project-name@project-domain-name
			ba.Scope = new(gophercloud.AuthScope)
			// assume domains are always prefixed with @
			if scopeParts[0] != "" {
				ba.Scope.ProjectName = scopeParts[0]
			}
			ba.Scope.DomainName = scopeParts[1]
		} else if len(scopeParts) >= 1 {
			// project-id
			ba.Scope = &gophercloud.AuthScope{ProjectID: scopeParts[0]}
		} else if guessScope {
			// not defined: choose an arbitrary project where the user has access (needed for UX reasons)
			if err := d.guessScope(&ba); err != nil {
				return nil, err
			}
		}

		// finall set the password
		ba.Password = password
	} else {
		return nil, NewAuthenticationError(StatusMissingCredentials, "Authorization header missing (no username/password or token)")
	}

	// check overriding project/domain via ULR param, so end-users can encode this in the URL (e.g. for bookmarks)
	if projectID := query.Get("project_id"); projectID != "" {
		ba.Scope = &gophercloud.AuthScope{ProjectID: projectID}
		query.Del("project_id")
	} else if domainID := query.Get("domain_id"); domainID != "" {
		ba.Scope = &gophercloud.AuthScope{DomainID: domainID}
		query.Del("domain_id")
	} else if ba.TokenID == "" && ba.Scope == nil {
		// fail if we end up with no scope
		return nil, NewAuthenticationError(StatusMissingCredentials, "Basic authorization credentials missing OpenStack authorization scope part")
	}

	return &ba, nil
}

func (d *keystone) guessScope(ba *gophercloud.AuthOptions) AuthenticationError {
	// guess scope if it is missing
	userID := ba.UserID
	var err error
	if userID == "" {
		userID, err = d.UserID(ba.Username, ba.DomainName)
		if err != nil {
			return NewAuthenticationError(StatusWrongCredentials, err.Error())
		}
	}
	userprojects, err := d.UserProjects(userID)
	if err != nil {
		return NewAuthenticationError(StatusNotAvailable, err.Error())
	} else if len(userprojects) == 0 {
		return NewAuthenticationError(StatusNoPermission, "User %s (%s@%s) does not have monitoring authorization on any project in any domain (required roles: %s)", userID, ba.Username, ba.DomainName, viper.GetString("keystone.roles"))
	}

	// default to first project (note that redundant attributes are not copied here to aovid errors)
	ba.Scope = &gophercloud.AuthScope{ProjectID: userprojects[0].ProjectID}
	if ba.Scope.ProjectID == "" {
		ba.Scope.DomainID = userprojects[0].DomainID
	}

	return nil
}

// authenticate authenticates a user using OpenStack credentials.
// Those credentials can be username+password, token or application credentials.
// The parameter `asServiceUser` controls the behaviour: as a service user the method will validate incoming tokens
// in order to determine the user roles. As a non-service user it will merely request a token from the passed credentials
// and obtain an endpoint for the Maia service. Both cases will create a token when username and password or OpenStack application
// credentials are passed in.
// `rescope` will be set to `true` to indicate that the token passed needs to be used to create a new token
// because the scope should be changed.
// It returns the authorization context
func (d *keystone) authenticate(authOpts gophercloud.AuthOptions, asServiceUser, rescope bool) (*policy.Context, string, AuthenticationError) {
	// check cache, but ignore the result if tokens are rescoped
	if entry, found := d.tokenCache.Get(authOpts2StringKey(authOpts)); found && (authOpts.Scope == nil || authOpts.Scope.ProjectID == entry.(*cacheEntry).context.Auth["project_id"]) {
		if authOpts.TokenID != "" {
			util.LogDebug("Token cache hit: token %s... for scope %+v", authOpts.TokenID[:1+len(authOpts.TokenID)/4], authOpts.Scope)
		} else {
			util.LogDebug("Token cache hit: user %s%s and password ***** for scope %+v", authOpts.Username, authOpts.UserID, authOpts.Scope)
		}
		return entry.(*cacheEntry).context, entry.(*cacheEntry).endpointURL, nil
	}

	var tokenData keystoneToken
	var endpointURL string
	if authOpts.TokenID != "" && asServiceUser && !rescope {
		// token passed, scope is empty since it is part of the token (no username password given)
		util.LogDebug("verify token")
		response := tokens.Get(d.providerClient, authOpts.TokenID)
		if response.Err != nil {
			//this includes 4xx responses, so after this point, we can be sure that the token is valid
			return nil, "", NewAuthenticationError(StatusWrongCredentials, response.Err.Error())
		}
		err := response.ExtractInto(&tokenData)
		if err != nil {
			return nil, "", NewAuthenticationError(StatusNotAvailable, err.Error())
		}
		// detect rescoping
		if authOpts.Scope != nil && authOpts.Scope.ProjectID != tokenData.ProjectScope.ID {
			util.LogDebug("scope change detected")
			return d.authenticate(authOpts, asServiceUser, true)
		}
		tokenInfo, err := response.ExtractToken()
		if err != nil {
			return nil, "", NewAuthenticationError(StatusNotAvailable, err.Error())
		}
		tokenData.Token = tokenInfo.ID
		catalog, err := response.ExtractServiceCatalog()
		if err != nil {
			return nil, "", NewAuthenticationError(StatusNotAvailable, err.Error())
		}
		// service endpoint
		endpointURL, err = openstack.V3EndpointURL(catalog, gophercloud.EndpointOpts{Type: "metrics", Availability: gophercloud.AvailabilityPublic})
		if err != nil {
			return nil, "", NewAuthenticationError(StatusNotAvailable, err.Error())
		}
	} else {
		// no token or changed scoped: need to authenticate user
		util.LogDebug("authenticate user %s%s with scope %+v.", authOpts.Username, authOpts.UserID, authOpts.Scope)
		// create new token from basic authentication credentials or token ID
		var tokenID string
		client, err := openstack.AuthenticatedClient(authOpts)
		if client != nil {
			tokenID, err = client.GetAuthResult().ExtractTokenID()
		}
		if err != nil {
			statusCode := StatusWrongCredentials
			//this includes 4xx responses, so after this point, we can be sure that the token is valid
			if authOpts.Username != "" || authOpts.UserID != "" {
				util.LogInfo("Failed login of user name %s%s for scope %+v: %s", authOpts.Username, authOpts.UserID, authOpts.Scope, err.Error())
			} else if authOpts.TokenID != "" {
				util.LogInfo("Failed login of with token %s... for scope %+v: %s", authOpts.TokenID[:1+len(authOpts.TokenID)/4], authOpts.Scope, err.Error())
			} else if authOpts.ApplicationCredentialID != "" {
				util.LogInfo("Failed login of application credential ID %s: %s", authOpts.ApplicationCredentialID, err.Error())
			} else if authOpts.ApplicationCredentialName != "" {
				util.LogInfo("Failed login of application credential ID %s: %s", authOpts.ApplicationCredentialName, err.Error())
			} else {
				statusCode = StatusMissingCredentials
			}
			return nil, "", NewAuthenticationError(statusCode, err.Error())
		}
		util.LogDebug("token creation/rescoping successful, authenticating with token")

		if asServiceUser {
			// recurse in order to obtain catalog entry; login in via token, to provide scope information
			var ce cacheEntry
			var authErr AuthenticationError
			ce.context, ce.endpointURL, authErr = d.authenticate(gophercloud.AuthOptions{IdentityEndpoint: authOpts.IdentityEndpoint, TokenID: tokenID}, asServiceUser, false)
			if authErr == nil && authOpts.TokenID == "" {
				// cache basic / application credential authentication results in the same way as token validations
				util.LogDebug("Add cache entry for username %s%s for scope %+v", authOpts.UserID, authOpts.Username, authOpts.Scope)
				d.tokenCache.Set(authOpts2StringKey(authOpts), &ce, cache.DefaultExpiration)
			}
			return ce.context, ce.endpointURL, authErr
		}
		// else populate from input
		tokenData.Token = tokenID
		tokenData.User.ID = authOpts.UserID
		tokenData.User.Name = authOpts.Username
		tokenData.User.Domain.ID = authOpts.DomainID
		tokenData.User.Domain.Name = authOpts.DomainName
		if authOpts.Scope != nil {
			tokenData.ProjectScope.ID = authOpts.Scope.ProjectID
			tokenData.ProjectScope.Name = authOpts.Scope.ProjectName
			tokenData.DomainScope.ID = authOpts.Scope.DomainID
			tokenData.ProjectScope.Name = authOpts.Scope.DomainName
		} else if authOpts.ApplicationCredentialName != "" || authOpts.ApplicationCredentialID != "" {
			tokenData.Application.ID = authOpts.ApplicationCredentialID
			tokenData.Application.Name = authOpts.ApplicationCredentialName
		}

		endpointURL, err = client.EndpointLocator(metricsEndpointOpts)
		if err != nil {
			return nil, "", NewAuthenticationError(StatusNotAvailable, err.Error())
		}
	}

	// authorization context
	context := tokenData.ToContext()

	// update the cache
	ce := cacheEntry{
		context:     &context,
		endpointURL: endpointURL,
	}

	util.LogDebug("add token cache entry for token %s... for scope %+v", tokenData.Token[:1+len(tokenData.Token)/4], authOpts.Scope)
	d.tokenCache.Set(authOpts2StringKey(authOpts), &ce, cache.DefaultExpiration)
	return &context, endpointURL, nil
}

func (d *keystone) ChildProjects(projectID string) ([]string, error) {
	if ce, ok := d.projectTreeCache.Get(projectID); ok {
		return ce.([]string), nil
	}

	childprojects, err := d.fetchChildProjects(projectID)
	if err != nil {
		util.LogError("Unable to obtain project tree of project %s: %s", projectID, err.Error)
		return nil, err
	}

	d.projectTreeCache.Set(projectID, childprojects, cache.DefaultExpiration)
	return childprojects, nil
}

// fetchChildProjects builds the full hierarchy of child-projects. This is used
// e.g. to compute the right project_id filter expression in the PromQL queries
// generated by Maia
func (d *keystone) fetchChildProjects(projectID string) ([]string, error) {
	projectIDs := []string{}
	enabledVal := true
	// iterate of all pages returned by the list-projects API call
	err := projects.List(d.providerClient, projects.ListOpts{ParentID: projectID, Enabled: &enabledVal}).EachPage(func(page pagination.Page) (bool, error) {
		slice, err := projects.ExtractProjects(page)
		if err != nil {
			return false, err
		}
		for _, p := range slice {
			projectIDs = append(projectIDs, p.ID)
			//  recurse
			children, err := d.fetchChildProjects(p.ID)
			if err != nil {
				return false, err
			}
			projectIDs = append(projectIDs, children...)
		}

		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return projectIDs, nil
}

func (d *keystone) UserProjects(userID string) ([]tokens.Scope, error) {
	if up, ok := d.userProjectsCache.Get(userID); ok {
		return up.([]tokens.Scope), nil
	}

	up, err := d.fetchUserProjects(userID)
	if err != nil {
		util.LogError("Unable to obtain monitoring project list of user %s: %v", userID, err)
		return nil, err
	}

	// cache should be updated at this point
	d.userProjectsCache.Set(userID, up, cache.DefaultExpiration)
	return up, nil
}

// fetchUserProjects lists all projects (i.e. scopes) the user may access using Keystone (no cache lookup)
func (d *keystone) fetchUserProjects(userID string) ([]tokens.Scope, error) {
	scopes := []tokens.Scope{}
	effectiveVal := true
	// iterate of all pages returned by the list-role-assignments API call
	err := roles.ListAssignments(d.providerClient, roles.ListAssignmentsOpts{UserID: userID, Effective: &effectiveVal}).EachPage(func(page pagination.Page) (bool, error) {
		util.LogDebug("loading role assignment page")
		slice, err := roles.ExtractRoleAssignments(page)
		if err != nil {
			return false, err
		}
		for _, ra := range slice {
			if _, ok := d.monitoringRoles[ra.Role.ID]; ok && ra.Scope.Project.ID != "" {
				scope, ok := d.projectScopeCache.Get(ra.Scope.Project.ID)
				if !ok {
					project, err := projects.Get(d.providerClient, ra.Scope.Project.ID).Extract()
					if err != nil {
						return false, err
					}
					domainName := d.domainNames[project.DomainID] // this will panic if domains have been added meanwhile --> USE AS A TRIGGER TO RELOAD?
					scope = tokens.Scope{ProjectID: ra.Scope.Project.ID, ProjectName: project.Name, DomainID: project.DomainID, DomainName: domainName}
					d.projectScopeCache.Set(ra.Scope.Project.ID, scope, cache.DefaultExpiration)
				}
				scopes = append(scopes, scope.(tokens.Scope))
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	return scopes, nil
}

func (d *keystone) UserID(username, userDomain string) (string, error) {
	key := username + "@" + userDomain
	if ce, ok := d.userIDCache.Get(key); ok {
		return ce.(string), nil
	}

	id, err := d.fetchUserID(username, userDomain)
	if err != nil {
		return "", err
	}

	d.userIDCache.Set(key, id, cache.DefaultExpiration)

	return id, nil
}

// fetchUserID determines the ID of a user of a given qualified name using Keystone (no cache lookup)
func (d *keystone) fetchUserID(username, userDomain string) (string, error) {
	userDomainID := d.domainIDs[userDomain]
	userID := ""
	enabled := true
	err := users.List(d.providerClient, users.ListOpts{Name: username, DomainID: userDomainID, Enabled: &enabled}).EachPage(func(page pagination.Page) (bool, error) {
		users, err := users.ExtractUsers(page)
		if err != nil {
			return false, err
		}
		for _, user := range users {
			userID = user.ID
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return "", err
	}

	if userID == "" {
		err = fmt.Errorf("no such user %s@%s", username, userDomain)
	}

	return userID, err
}
