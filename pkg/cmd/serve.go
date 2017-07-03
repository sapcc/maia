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
	"github.com/sapcc/maia/pkg/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

// serveCmd represents the get command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Maia service",
	Long:  "Run the Maia service against a Prometheus backend collecting the metrics.",
	RunE: func(cmd *cobra.Command, args []string) (ret error) {
		// transform panics with error params into errors
		defer func() {
			if r := recover(); r != nil {
				fmt.Println(r)
			}
		}()

		if _, err := os.Stat(configFile); err != nil {
			panic(fmt.Errorf("No config file found at %s (required for server mode)", configFile))
		}

		// just run the server
		api.Server()

		return nil
	},
}

func init() {
	RootCmd.AddCommand(serveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// metricsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// metricsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	var promUrl, bindAddr, policyFile string

	serveCmd.Flags().StringVarP(&promUrl, "prometheus-url", "p", "", "URL of the Prometheus server backing Maia")
	viper.BindPFlag("maia.prometheus_url", serveCmd.Flags().Lookup("prometheus-url"))
	serveCmd.Flags().StringVarP(&bindAddr, "bind-address", "b", "", "IP-Address and port where Maia is listening for incoming requests (e.g. 0.0.0.0:9091)")
	viper.BindPFlag("maia.bind_address", serveCmd.Flags().Lookup("bind-address"))
	serveCmd.Flags().StringVarP(&policyFile, "policy-file", "r", "", "Location of the OpenStack policy file")
	viper.BindPFlag("maia.policy_file", serveCmd.Flags().Lookup("policy-file"))
}
