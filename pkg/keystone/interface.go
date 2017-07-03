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
	"github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/spf13/viper"
	"net/http"
)

// Driver is an interface that wraps the authentication of the service user and
// token checking of API users. Because it is an interface, the real implementation
// can be mocked away in unit tests.
type Driver interface {
	// AuthenticateRequest authenticates a user using authOptionsFromRequest passed in the HTTP request header.
	// After successful authentication, additional context information is added to the request header
	// In addition a Context object is returned.
	AuthenticateRequest(req *http.Request) (*policy.Context, error)

	// Authenticate authenticates a user using the provided authOptionsFromRequest
	Authenticate(options *tokens.AuthOptions, serviceUser bool) (*policy.Context, error)
}

// NewKeystoneDriver is a factory method which chooses the right driver implementation based on configuration settings
func NewKeystoneDriver() Driver {
	driverName := viper.GetString("maia.keystone_driver")
	switch driverName {
	case "keystone":
		return Keystone()
	case "mock":
		return Mock()
	default:
		panic(fmt.Errorf("Couldn't match a keystone driver for configured value \"%s\"", driverName))
	}
}
