// SPDX-FileCopyrightText: 2017 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package keystone

import (
	"context"
	"fmt"

	"net/http"
	"net/url"
	"sync"

	"regexp"
	"strings"
	"time"

	policy "github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/users"
	"github.com/gophercloud/gophercloud/v2/pagination"
	cache "github.com/patrickmn/go-cache"
	"github.com/spf13/viper"

	"github.com/sapcc/go-bits/logg"
)

var metricsEndpointOpts = gophercloud.EndpointOpts{Type: "metrics", Availability: gophercloud.AvailabilityPublic}

// Keystone creates a real keystone authentication and authorization driver
func Keystone() Driver {
	ks := keystone{}
	ks.init()

	return &ks
}

// KeystoneWithSection builds a keystone driver using a specific config section
func KeystoneWithSection(configSection string) Driver {
	ks := keystone{
		configSection: configSection,
	}
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
	// Configuration section for viper keys
	configSection string
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
		ctx := context.Background()
		_, err := d.serviceKeystoneClient(ctx)
		if err != nil {
			panic(err)
		}
	}
}

// serviceKeystoneClient creates and returns the keystone connection used by the running service
func (d *keystone) serviceKeystoneClient(ctx context.Context) (*gophercloud.ServiceClient, error) {
	d.serviceConnMutex.Lock()
	defer d.serviceConnMutex.Unlock()

	if d.providerClient == nil {
		section := "keystone"
		if d.configSection != "" {
			section = "keystone." + d.configSection
		}

		logg.Info("Setting up identity connection to %s", viper.GetString(section+".auth_url"))
		client, err := newKeystoneClient(ctx, d.authOptionsFromConfig())
		if err != nil {
			return nil, err
		}
		d.providerClient = client
		// load the list of all domains and roles to avoid frequent API calls
		// runtime changes are not detected
		d.loadDomainsAndRoles(ctx)
	}

	return d.providerClient, nil
}

// newKeystoneClient establishes a keystone connection
func newKeystoneClient(ctx context.Context, authOpts gophercloud.AuthOptions) (*gophercloud.ServiceClient, error) {
	provider, err := openstack.AuthenticatedClient(ctx, authOpts)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize OpenStack service user provider client: %w", err)
	}
	if viper.IsSet("maia.proxy") {
		proxyURL, err := url.Parse(viper.GetString("maia.proxy"))
		if err != nil {
			logg.Error("Could not set proxy for gophercloud client: %s .\n%s", proxyURL, err.Error())
			return nil, err
		}
		provider.HTTPClient.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}
	client, err := openstack.NewIdentityV3(provider, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("cannot initialize OpenStack service user identity V3 client: %w", err)
	}

	return client, nil
}

// keystoneToken combines all parts of a get-token result into a single struct.
// It replaces the need to call multiple
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

// ToContext converts the keystoneToken structure
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
		Logger: func(format string, args ...any) {
			logg.Debug(format, args...)
		},
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
func (d *keystone) loadDomainsAndRoles(ctx context.Context) {
	logg.Info("Loading/refreshing global list of domains and roles")

	allRoles := struct {
		Roles []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"roles"`
	}{}

	u := d.providerClient.ServiceURL("roles")
	resp, err := d.providerClient.Get(ctx, u, &allRoles, nil)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// get list of all monitoring role names
	rolesNames := strings.Split(viper.GetString("keystone.roles"), ",")

	d.monitoringRoles = map[string]string{}
	// get all roles and match them with our list to get the ID
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
	err = projects.List(d.providerClient, projects.ListOpts{IsDomain: &trueVal, Enabled: &trueVal}).EachPage(ctx, func(ctx context.Context, page pagination.Page) (bool, error) {
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
func (d *keystone) authOptionsFromConfig() gophercloud.AuthOptions {
	section := "keystone"
	if d.configSection != "" {
		section = "keystone." + d.configSection
	}

	return gophercloud.AuthOptions{
		IdentityEndpoint: viper.GetString(section + ".auth_url"),
		TokenID:          viper.GetString(section + ".token"),
		Username:         viper.GetString(section + ".username"),
		Password:         viper.GetString(section + ".password"),
		DomainName:       viper.GetString(section + ".user_domain_name"),
		AllowReauth:      true,
		Scope: &gophercloud.AuthScope{
			ProjectName: viper.GetString(section + ".project_name"),
			DomainName:  viper.GetString(section + ".project_domain_name"),
		},
	}
}

// getAuthURL returns the auth URL for the configured keystone section
func (d *keystone) getAuthURL() string {
	section := "keystone"
	if d.configSection != "" {
		section = "keystone." + d.configSection
	}
	return viper.GetString(section + ".auth_url")
}

// authOpts2StringKey builds a secure context-aware cache key that prevents collisions
// between different keystone instances (regional vs global)
func (d *keystone) authOpts2StringKey(authOpts gophercloud.AuthOptions) string {
	// Get keystone context for this instance
	keystoneContext := d.getKeystoneContext()

	// the key of a token is the token itself, but include context for isolation
	if authOpts.TokenID != "" {
		return fmt.Sprintf("%s|CTX:%s", authOpts.TokenID, keystoneContext)
	}

	// build unique key by separating fields with blanks. Since blanks are not allowed in several of those
	// the result will be unique

	var baseKey string
	// for Application Credentials there will be no scope so it can't be used to store the token
	if authOpts.ApplicationCredentialID != "" || authOpts.ApplicationCredentialName != "" {
		baseKey = authOpts.UserID + " " + authOpts.Username + " " + authOpts.Password + " " + authOpts.DomainID + " " +
			authOpts.DomainName + " " + authOpts.ApplicationCredentialID + " " + authOpts.ApplicationCredentialName + " " +
			authOpts.ApplicationCredentialSecret
	} else {
		// for basic authentication credentials we need to take into account the scoping information as well
		baseKey = authOpts.UserID + " " + authOpts.Username + " " + authOpts.Password + " " + authOpts.DomainID + " " +
			authOpts.DomainName + " " + authOpts.Scope.ProjectID + " " + authOpts.Scope.ProjectName + " " +
			authOpts.Scope.DomainID + " " + authOpts.Scope.DomainName
	}

	// Add explicit context to prevent collisions
	return fmt.Sprintf("%s|CTX:%s", baseKey, keystoneContext)
}

// getKeystoneContext determines the keystone context for this instance
func (d *keystone) getKeystoneContext() string {
	if d.configSection == "" {
		return "regional"
	}
	return d.configSection // "global", etc.
}

// Authenticate authenticates a non-service user using available authOptionsFromRequest (username+password or token)
// It returns the authorization context
func (d *keystone) Authenticate(ctx context.Context, authOpts gophercloud.AuthOptions) (*policy.Context, string, AuthenticationError) {
	return d.authenticate(ctx, authOpts, false, false)
}

// AuthenticateRequest attempts to Authenticate a user using the request header contents
// The resulting policy context can be used to authorize the user
// If no supported authOptionsFromRequest could be found, the context is nil
// If the authOptionsFromRequest are invalid or the authentication provider has issues, an error is returned
// When guessScope is set to true, the method will try to find a suitible project when the scope is not defined (basic auth. only)
func (d *keystone) AuthenticateRequest(ctx context.Context, r *http.Request, guessScope bool) (*policy.Context, AuthenticationError) {
	authOpts, err := d.authOptionsFromRequest(ctx, r, guessScope)
	if err != nil {
		logg.Error(err.Error())
		return nil, err
	}

	// if the request does not have a keystone token, then a token must be requested on behalf of the client
	// prevents wrong credentials from causing service user reauthentication
	policyContext, _, err := d.authenticate(ctx, *authOpts, true, false)
	if err != nil {
		return nil, err
	}

	// policy Context fields are copied into request headers
	// so that we do not have to add an extra parameter to every function.
	r.Header.Set("X-User-Id", policyContext.Auth["user_id"])
	r.Header.Set("X-User-Name", policyContext.Auth["user_name"])
	r.Header.Set("X-User-Domain-Id", policyContext.Auth["user_domain_id"])
	r.Header.Set("X-User-Domain-Name", policyContext.Auth["user_domain_name"])
	r.Header.Set("X-Application-Credential-Id", policyContext.Auth["application_credential_id"])
	r.Header.Set("X-Application-Credential-Name", policyContext.Auth["application_credential_name"])
	r.Header.Set("X-Application-Credential-Secret", policyContext.Auth["application_credential_secret"])

	// Strip any client-supplied scope headers first, then set them only from the
	// validated token claims. Downstream scope resolution (scopeToLabelConstraint)
	// trusts these headers as the tenant boundary; a forged inbound X-Project-Id on
	// a domain-scoped token would otherwise survive and leak another tenant's
	// metrics (the domain branch below sets no project header). Same rationale as
	// the X-Roles Del below.
	r.Header.Del("X-Project-Id")
	r.Header.Del("X-Project-Name")
	r.Header.Del("X-Project-Domain-Id")
	r.Header.Del("X-Project-Domain-Name")
	r.Header.Del("X-Domain-Id")
	r.Header.Del("X-Domain-Name")
	if policyContext.Auth["project_id"] != "" {
		// user is scoped to project
		r.Header.Set("X-Project-Id", policyContext.Auth["project_id"])
		r.Header.Set("X-Project-Name", policyContext.Auth["project_name"])
		r.Header.Set("X-Project-Domain-Id", policyContext.Auth["project_domain_id"])
		r.Header.Set("X-Project-Domain-Name", policyContext.Auth["project_domain_name"])
	} else {
		// user is scoped to domain
		r.Header.Set("X-Domain-Id", policyContext.Auth["domain_id"])
		r.Header.Set("X-Domain-Name", policyContext.Auth["domain_name"])
	}
	// Emit roles as a single comma-joined header. Del first so a
	// client-supplied X-Roles cannot survive and be trusted downstream; the
	// consumers (Whoami, the authorization error message) split on ",".
	// Assumes Keystone role names contain no commas (they don't), otherwise a
	// name would be silently split at the wrong boundary on read.
	r.Header.Del("X-Roles")
	if len(policyContext.Roles) > 0 {
		r.Header.Set("X-Roles", strings.Join(policyContext.Roles, ","))
	}
	r.Header.Set("X-Auth-Token", policyContext.Auth["token"])
	r.Header.Set("X-Auth-Token-Expiry", policyContext.Auth["token-expiry"])

	return policyContext, nil
}

// authOptionsFromRequest retrieves authOptionsFromRequest from http request and puts them into an AuthOptions structure
// It requires username to contain a qualified OpenStack username and project/domain scope information
// Format: <user>"|"<project> or <user>"|@"<domain>
// user/project can either be a unique OpenStack ID or a qualified name with domain information, e.g. username"@"domain
// When guessScope is set to true, the method will try to find a suitible project when the scope is not defined (basic auth. only)
// You can also specify the scope as URL query param
func (d *keystone) authOptionsFromRequest(ctx context.Context, r *http.Request, guessScope bool) (*gophercloud.AuthOptions, AuthenticationError) {
	ba := gophercloud.AuthOptions{
		IdentityEndpoint: d.getAuthURL(),
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
		// relocate to header
		query.Del("x-auth-token")
		r.URL.RawQuery = query.Encode()
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
			// default to arbitrary project with sufficient roles for the user
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
		switch {
		case len(scopeParts) >= 2:
			// project-name@project-domain-name
			ba.Scope = new(gophercloud.AuthScope)
			// assume domains are always prefixed with @
			if scopeParts[0] != "" {
				ba.Scope.ProjectName = scopeParts[0]
			}
			ba.Scope.DomainName = scopeParts[1]
		case len(scopeParts) >= 1:
			// project-id
			ba.Scope = &gophercloud.AuthScope{ProjectID: scopeParts[0]}
		case guessScope:
			// not defined: choose an arbitrary project where the user has access (needed for UX reasons)
			if err := d.guessScope(ctx, &ba); err != nil {
				return nil, err
			}
		}

		// set the password
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

func (d *keystone) guessScope(ctx context.Context, ba *gophercloud.AuthOptions) AuthenticationError {
	// guess scope if it is missing
	userID := ba.UserID
	var err error
	if userID == "" {
		userID, err = d.UserID(ctx, ba.Username, ba.DomainName)
		if err != nil {
			return NewAuthenticationError(StatusWrongCredentials, "%s", err.Error())
		}
	}
	userprojects, err := d.UserProjects(ctx, userID)
	if err != nil {
		return NewAuthenticationError(StatusNotAvailable, "%s", err.Error())
	} else if len(userprojects) == 0 {
		return NewAuthenticationError(StatusNoPermission, "User %s (%s@%s) does not have monitoring authorization on any project in any domain (required roles: %s)", userID, ba.Username, ba.DomainName, viper.GetString("keystone.roles"))
	}

	// default to primary project (note that redundant attributes are not copied here to avoid errors)
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
// `rescope` when `true` indicates that the token passed requires creation of a token
// because the scope requires modification.
// It returns the authorization context
func (d *keystone) authenticate(ctx context.Context, authOpts gophercloud.AuthOptions, asServiceUser, rescope bool) (*policy.Context, string, AuthenticationError) {
	// Use secure contextual cache key for lookup
	cacheKey := d.authOpts2StringKey(authOpts)

	// Get keystone context for logging
	keystoneContext := d.getKeystoneContext()

	// check cache, but ignore the result if tokens are rescoped
	if entry, found := d.tokenCache.Get(cacheKey); found && !rescope && (authOpts.Scope == nil || authOpts.Scope.ProjectID == entry.(*cacheEntry).context.Auth["project_id"]) {
		if authOpts.TokenID != "" {
			logg.Debug("[%s-keystone] Token cache hit: token %s... for scope %+v", keystoneContext, authOpts.TokenID[:1+len(authOpts.TokenID)/4], authOpts.Scope)
		} else {
			logg.Debug("[%s-keystone] Token cache hit: user %s%s and password ***** for scope %+v", keystoneContext, authOpts.Username, authOpts.UserID, authOpts.Scope)
		}
		return entry.(*cacheEntry).context, entry.(*cacheEntry).endpointURL, nil
	}

	var tokenData keystoneToken
	var endpointURL string
	if authOpts.TokenID != "" && asServiceUser && !rescope {
		// token passed, scope is empty since it is part of the token (no username password given)
		logg.Debug("verify token")
		response := tokens.Get(ctx, d.providerClient, authOpts.TokenID)
		if response.Err != nil {
			// this includes 4xx responses, so after this point, we can be sure that the token is valid
			return nil, "", NewAuthenticationError(StatusWrongCredentials, "%s", response.Err.Error())
		}
		err := response.ExtractInto(&tokenData)
		if err != nil {
			return nil, "", NewAuthenticationError(StatusNotAvailable, "%s", err.Error())
		}
		// detect rescoping
		if authOpts.Scope != nil && authOpts.Scope.ProjectID != tokenData.ProjectScope.ID {
			logg.Debug("scope change detected")
			return d.authenticate(ctx, authOpts, asServiceUser, true)
		}
		tokenInfo, err := response.ExtractToken()
		if err != nil {
			return nil, "", NewAuthenticationError(StatusNotAvailable, "%s", err.Error())
		}
		tokenData.Token = tokenInfo.ID
		catalog, err := response.ExtractServiceCatalog()
		if err != nil {
			return nil, "", NewAuthenticationError(StatusNotAvailable, "%s", err.Error())
		}
		// service endpoint
		endpointURL, err = openstack.V3Endpoint(ctx, d.providerClient.ProviderClient, catalog, gophercloud.EndpointOpts{Type: "metrics", Availability: gophercloud.AvailabilityPublic})
		if err != nil {
			return nil, "", NewAuthenticationError(StatusNotAvailable, "%s", err.Error())
		}
	} else {
		// no token or rescoped: authenticate user
		logg.Debug("authenticate user %s%s with scope %+v.", authOpts.Username, authOpts.UserID, authOpts.Scope)
		// create token from basic authentication credentials or token ID
		var tokenID string
		client, err := openstack.AuthenticatedClient(ctx, authOpts)
		if client != nil {
			tokenID, err = client.GetAuthResult().ExtractTokenID()
		}
		if err != nil {
			statusCode := StatusWrongCredentials
			// this includes 4xx responses, so after this point, we can be sure that the token is valid
			switch {
			case authOpts.Username != "" || authOpts.UserID != "":
				logg.Info("Failed login of user name %s%s for scope %+v: %s", authOpts.Username, authOpts.UserID, authOpts.Scope, err.Error())
			case authOpts.TokenID != "":
				logg.Info("Failed login of with token %s... for scope %+v: %s", authOpts.TokenID[:1+len(authOpts.TokenID)/4], authOpts.Scope, err.Error())
			case authOpts.ApplicationCredentialID != "":
				logg.Info("Failed login of application credential ID %s: %s", authOpts.ApplicationCredentialID, err.Error())
			case authOpts.ApplicationCredentialName != "":
				logg.Info("Failed login of application credential ID %s: %s", authOpts.ApplicationCredentialName, err.Error())
			default:
				statusCode = StatusMissingCredentials
			}

			return nil, "", NewAuthenticationError(statusCode, "%s", err.Error())
		}
		logg.Debug("token creation/rescoping successful, authenticating with token")

		if asServiceUser {
			// recurse in order to obtain catalog entry; login in via token, to provide scope information
			var ce cacheEntry
			var authErr AuthenticationError
			ce.context, ce.endpointURL, authErr = d.authenticate(ctx, gophercloud.AuthOptions{IdentityEndpoint: authOpts.IdentityEndpoint, TokenID: tokenID}, asServiceUser, false)
			if authErr == nil && authOpts.TokenID == "" {
				// cache basic and application credential authentication like token validations
				basicAuthCacheKey := d.authOpts2StringKey(authOpts)
				logg.Debug("[%s-keystone] Cache entry for username %s%s for scope %+v", keystoneContext, authOpts.UserID, authOpts.Username, authOpts.Scope)
				d.tokenCache.Set(basicAuthCacheKey, &ce, cache.DefaultExpiration)
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
			return nil, "", NewAuthenticationError(StatusNotAvailable, "%s", err.Error())
		}
	}

	// authorization context
	policyContext := tokenData.ToContext()

	// update the cache
	ce := cacheEntry{
		context:     &policyContext,
		endpointURL: endpointURL,
	}

	logg.Debug("[%s-keystone] Token cache entry for token %s... for scope %+v", keystoneContext, tokenData.Token[:1+len(tokenData.Token)/4], authOpts.Scope)
	d.tokenCache.Set(cacheKey, &ce, cache.DefaultExpiration)
	return &policyContext, endpointURL, nil
}

func (d *keystone) ChildProjects(ctx context.Context, projectID string) ([]string, error) {
	keystoneContext := d.getKeystoneContext()
	logg.Debug("[CHILD_PROJECTS_DEBUG] [%s-keystone] ChildProjects called for project: %s", keystoneContext, projectID)

	if ce, ok := d.projectTreeCache.Get(projectID); ok {
		cached := ce.([]string)
		logg.Debug("[CHILD_PROJECTS_DEBUG] [%s-keystone] Cache hit for %s: %v", keystoneContext, projectID, cached)
		return cached, nil
	}

	logg.Debug("[CHILD_PROJECTS_DEBUG] [%s-keystone] Cache miss for %s, fetching from keystone", keystoneContext, projectID)
	childprojects, err := d.fetchChildProjects(ctx, projectID)
	if err != nil {
		logg.Error("[CHILD_PROJECTS_DEBUG] [%s-keystone] Unable to obtain project tree of project %s: %s", keystoneContext, projectID, err.Error())
		return nil, err
	}

	logg.Debug("[CHILD_PROJECTS_DEBUG] [%s-keystone] Fetched child projects for %s: %v", keystoneContext, projectID, childprojects)
	d.projectTreeCache.Set(projectID, childprojects, cache.DefaultExpiration)
	return childprojects, nil
}

// fetchChildProjects builds the full hierarchy of child-projects. This is used
// e.g. to compute the right project_id filter expression in the PromQL queries
// generated by Maia
func (d *keystone) fetchChildProjects(ctx context.Context, projectID string) ([]string, error) {
	projectIDs := []string{}
	enabledVal := true
	// iterate of all pages returned by the list-projects API call
	err := projects.List(d.providerClient, projects.ListOpts{ParentID: projectID, Enabled: &enabledVal}).EachPage(ctx, func(ctx context.Context, page pagination.Page) (bool, error) {
		slice, err := projects.ExtractProjects(page)
		if err != nil {
			return false, err
		}
		for _, p := range slice {
			projectIDs = append(projectIDs, p.ID)
			//  recurse
			children, err := d.fetchChildProjects(ctx, p.ID)
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

func (d *keystone) UserProjects(ctx context.Context, userID string) ([]tokens.Scope, error) {
	if up, ok := d.userProjectsCache.Get(userID); ok {
		return up.([]tokens.Scope), nil
	}

	up, err := d.fetchUserProjects(ctx, userID)
	if err != nil {
		logg.Error("Unable to obtain monitoring project list of user %s: %v", userID, err)
		return nil, err
	}

	// cache contains the results at this point
	d.userProjectsCache.Set(userID, up, cache.DefaultExpiration)
	return up, nil
}

// fetchUserProjects lists all projects (i.e. scopes) the user may access using Keystone (no cache lookup)
func (d *keystone) fetchUserProjects(ctx context.Context, userID string) ([]tokens.Scope, error) {
	scopes := []tokens.Scope{}
	effectiveVal := true
	// iterate of all pages returned by the list-role-assignments API call
	err := roles.ListAssignments(d.providerClient, roles.ListAssignmentsOpts{UserID: userID, Effective: &effectiveVal}).EachPage(ctx, func(ctx context.Context, page pagination.Page) (bool, error) {
		logg.Debug("loading role assignment page")
		slice, err := roles.ExtractRoleAssignments(page)
		if err != nil {
			return false, err
		}
		for _, ra := range slice {
			if _, ok := d.monitoringRoles[ra.Role.ID]; ok && ra.Scope.Project.ID != "" {
				scope, ok := d.projectScopeCache.Get(ra.Scope.Project.ID)
				if !ok {
					project, err := projects.Get(ctx, d.providerClient, ra.Scope.Project.ID).Extract()
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

func (d *keystone) UserID(ctx context.Context, username, userDomain string) (string, error) {
	key := username + "@" + userDomain
	if ce, ok := d.userIDCache.Get(key); ok {
		return ce.(string), nil
	}

	id, err := d.fetchUserID(ctx, username, userDomain)
	if err != nil {
		return "", err
	}

	d.userIDCache.Set(key, id, cache.DefaultExpiration)

	return id, nil
}

// fetchUserID determines the ID of a user of a given qualified name using Keystone (no cache lookup)
func (d *keystone) fetchUserID(ctx context.Context, username, userDomain string) (string, error) {
	userDomainID := d.domainIDs[userDomain]
	userID := ""
	enabled := true
	err := users.List(d.providerClient, users.ListOpts{Name: username, DomainID: userDomainID, Enabled: &enabled}).EachPage(ctx, func(ctx context.Context, page pagination.Page) (bool, error) {
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
