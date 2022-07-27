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

	policy "github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/spf13/viper"
)

const (
	// StatusNotAvailable means that the user could not be authenticated because the identity service is not available
	StatusNotAvailable = 1
	// StatusMissingCredentials means that the user provided invalid credentials and thus cannot be authenticated
	StatusMissingCredentials = 2
	// StatusWrongCredentials means that the user provided invalid credentials and thus cannot be authenticated
	StatusWrongCredentials = 3
	// StatusNoPermission means that the user could be authenticated but does not have access to the requested scope (no roles)
	StatusNoPermission = 4
	// StatusInternalError means that some internal error occurred. Retry makes sense
	StatusInternalError = 5
)

// AuthenticationError extends the error interface with a status code
type AuthenticationError interface {
	// error - embedding breaks mockgen
	// Error returns the error as string
	Error() string
	// StatusCode returns a machine-readable reason for the error (values correspond to http status codes)
	StatusCode() int
}

type authenticationError struct {
	AuthenticationError

	msg        string // description of error
	statusCode int    // status code (values correspond to http status codes)
}

func (e *authenticationError) Error() string {
	return e.msg
}

func (e *authenticationError) StatusCode() int {
	return e.statusCode
}

// NewAuthenticationError creates a new error instance
func NewAuthenticationError(statusCode int, format string, args ...interface{}) AuthenticationError {
	return &authenticationError{msg: fmt.Sprintf(format, args...), statusCode: statusCode}
}

// Driver is an interface that wraps the authentication of the service user and
// token checking of API users. Because it is an interface, the real implementation
// can be mocked away in unit tests.
type Driver interface {
	// AuthenticateRequest authenticates a user using authOptionsFromRequest passed in the HTTP request header.
	// After successful authentication, additional context information is added to the request header
	// In addition a Context object is returned for policy evaluation.
	// When guessScope is set to true, the method will try to find a suitible project when the scope is not defined (basic auth. only)
	AuthenticateRequest(req *http.Request, guessScope bool) (*policy.Context, AuthenticationError)

	// Authenticate authenticates a user using the provided authOptions.
	// It returns a context for policy evaluation and the public endpoint retrieved from the service catalog
	Authenticate(options gophercloud.AuthOptions) (*policy.Context, string, AuthenticationError)

	// ChildProjects returns the IDs of all child-projects of the project denoted by projectID
	ChildProjects(projectID string) ([]string, error)

	// UserProjects returns the project IDs and name of all projects where the current user has a monitoring role
	UserProjects(userID string) ([]tokens.Scope, error)

	// ServiceURL returns the service's global catalog entry
	// The result is empty when called from a client
	ServiceURL() string
}

// NewKeystoneDriver is a factory method which chooses the right driver implementation based on configuration settings
func NewKeystoneDriver() Driver {
	driverName := viper.GetString("maia.auth_driver")
	switch driverName {
	case "keystone":
		return Keystone()
	default:
		panic(fmt.Errorf("Couldn't match a keystone driver for configured value \"%s\"", driverName))
	}
}
