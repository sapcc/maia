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

package cmd

import (
	"fmt"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
	"os"
)

var maiaUrl string
var selector string
var auth tokens.AuthOptions

// metricsCmd represents the get command
var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Get actual metric values for project/domain.",
	Long:  "Lists all metric series and their current values. The series can filtered using selectors (label queries).",
	RunE: func(cmd *cobra.Command, args []string) (ret error) {
		// transform panics with error params into errors
		defer func() {
			if r := recover(); r != nil {
				fmt.Println(r)
			}
		}()

		context, err := keystone.NewKeystoneDriver().Authenticate(&auth, false)

		if err != nil {
			return err
		}

		// pass the keystone token to Maia and ensure that the result is JSON
		prometheus := storage.NewPrometheusDriver(maiaUrl, map[string]string{"X-Auth-Token": context.Auth["token"], "Accept": "text/plain"})

		var resp *http.Response
		resp, err = prometheus.Federate([]string{"{" + selector + "}"}, storage.PlainText)

		if err != nil {
			return err
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Print("Server responsed with error code %d: %s", resp.StatusCode, err.Error())
		} else {
			print(string(body))
		}

		return nil
	},
}

func init() {

	RootCmd.AddCommand(metricsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// metricsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// metricsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	metricsCmd.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", false, "Use JSON as output format")

	metricsCmd.Flags().StringVarP(&maiaUrl, "maia-url", "m", "", "URL of the target Maia service (override OpenStack service catalog)")
	metricsCmd.Flags().StringVarP(&selector, "selector", "l", "", "Prometheus label-selector to restrict the amount of metrics")

	// pass OpenStack auth. information via global top-level parameters or environment variables
	// it is used by the "serve" command as service user, otherwise to authenticate the client
	metricsCmd.PersistentFlags().StringVar(&auth.IdentityEndpoint, "os-auth-url", os.Getenv("OS_AUTH_URL"), "OpenStack Authentication URL")
	metricsCmd.PersistentFlags().StringVar(&auth.Username, "os-username", os.Getenv("OS_USERNAME"), "OpenStack Username")
	metricsCmd.PersistentFlags().StringVar(&auth.Password, "os-password", os.Getenv("OS_PASSWORD"), "OpenStack Password")
	metricsCmd.PersistentFlags().StringVar(&auth.DomainName, "os-user-domain-name", os.Getenv("OS_USER_DOMAIN_NAME"), "OpenStack User's domain name")
	metricsCmd.PersistentFlags().StringVar(&auth.Scope.ProjectName, "os-project-name", os.Getenv("OS_PROJECT_NAME"), "OpenStack Project name to scope to")
	metricsCmd.PersistentFlags().StringVar(&auth.Scope.DomainName, "os-project-domain-name", os.Getenv("OS_PROJECT_DOMAIN_NAME"), "OpenStack Project's domain name")
	metricsCmd.PersistentFlags().StringVar(&auth.Scope.DomainName, "os-domain-name", os.Getenv("OS_DOMAIN_NAME"), "OpenStack domain name to scope to")
	metricsCmd.PersistentFlags().StringVar(&auth.Scope.DomainID, "os-domain-id", os.Getenv("OS_DOMAIN_ID"), "OpenStack domain ID to scope to")
	metricsCmd.PersistentFlags().StringVar(&auth.TokenID, "os-token", os.Getenv("OS_TOKEN"), "OpenStack keystone token")

	viper.BindPFlag("keystone.auth_url", metricsCmd.PersistentFlags().Lookup("os-auth-url"))
}
