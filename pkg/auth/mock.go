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
	"github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud"
	"github.com/spf13/viper"
)

type mock struct{}

// Mock keystone implementation
func Mock() Driver {
	return mock{}
}

func (d mock) keystoneClient() (*gophercloud.ServiceClient, error) {
	return nil, nil
}

func (d mock) Client() *gophercloud.ProviderClient {
	return nil
}

//ListDomains implements the Driver interface.
func (d mock) ListDomains() ([]KeystoneDomain, error) {
	return nil, nil
}

//ListProjects implements the Driver interface.
func (d mock) ListProjects() ([]KeystoneProject, error) {
	return nil, nil
}

//CheckUserPermission implements the Driver interface.
func (d mock) ValidateToken(token string) (policy.Context, error) {

	return policy.Context{}, nil
}

func (d mock) Authenticate(credentials *gophercloud.AuthOptions) (policy.Context, error) {
	return policy.Context{Auth: map[string]string{"user_id": credentials.UserID, "project_id": credentials.TenantID, "password": credentials.Password}}, nil
}

func (d mock) AuthenticateUser(credentials *gophercloud.AuthOptions) (policy.Context, error) {
	return policy.Context{}, nil
}

func (d mock) DomainName(id string) (string, error) {
	return "default", nil
}

func (d mock) ProjectName(id string) (string, error) {
	return "master", nil
}

func (d mock) UserName(id string) (string, error) {
	return "myuser", nil
}

func (d mock) UserId(name string) (string, error) {
	return "eb5cd8f904b06e8b2a6eb86c8b04c08e6efb89b92da77905cc8c475f30b0b812", nil
}

func (d mock) AuthOptionsFromBasicAuthToken(tokenID string) *gophercloud.AuthOptions {
	return &gophercloud.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		TokenID:          tokenID,
	}
}

func (d mock) AuthOptionsFromBasicAuthCredentials(userID string, password string, projectId string) *gophercloud.AuthOptions {
	return &gophercloud.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		Username:         userID,
		Password:         password,
		// Note: gophercloud only allows for user & project in the same domain
		TenantID: projectId,
	}
}

func (d mock) AuthOptionsFromConfig() *gophercloud.AuthOptions {
	return &gophercloud.AuthOptions{
		IdentityEndpoint: viper.GetString("keystone.auth_url"),
		Username:         viper.GetString("keystone.username"),
		Password:         viper.GetString("keystone.password"),
		DomainName:       viper.GetString("keystone.user_domain_name"),
		// Note: gophercloud only allows for user & project in the same domain
		TenantName: viper.GetString("keystone.project_name"),
	}
}
