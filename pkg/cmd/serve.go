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
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sapcc/maia/pkg/api"
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
				fmt.Fprintln(os.Stderr, r)
			}
		}()

		// just run the server
		err := api.Server()
		if err != nil {
			return err
		}

		return nil
	},
	PreRun: func(cmd *cobra.Command, args []string) {
		if _, err := os.Stat(configFile); err != nil {
			panic(fmt.Errorf("no config file found at %s (required for server mode)", configFile))
		}

		readConfig(configFile)
	},
}

func readConfig(configPath string) {
	// Read the maia config file (required for server)
	// That way an OpenStack client environment will not be accidentally used for the "serve" command
	if _, err := os.Stat(configPath); err == nil {
		viper.SetConfigFile(configPath)
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		if err != nil { // Handle errors reading the config file
			panic(fmt.Errorf("fatal error config file: %s", err))
		}
	}
}

func init() {
	//	cobra.OnInitialize(func() {
	//		readConfig(configFile)
	//	})

	RootCmd.AddCommand(serveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// snapshotCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// snapshotCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	var bindAddr, policyFile string

	serveCmd.PersistentFlags().StringVar(&promURL, "prometheus-url", os.Getenv("MAIA_PROMETHEUS_URL"), "URL of the Prometheus server backing Maia (MAIA_PROMETHEUS_URL)")
	err := viper.BindPFlag("maia.prometheus_url", serveCmd.PersistentFlags().Lookup("prometheus-url"))
	if err != nil {
		panic(err)
	}
	serveCmd.Flags().StringVar(&bindAddr, "bind-address", "0.0.0.0:9091", "IP-Address and port where Maia is listening for incoming requests (e.g. 0.0.0.0:9091)")
	err = viper.BindPFlag("maia.bind_address", serveCmd.Flags().Lookup("bind-address"))
	if err != nil {
		panic(err)
	}
	serveCmd.Flags().StringVar(&policyFile, "policy-file", "", "Location of the OpenStack policy file")
	err = viper.BindPFlag("keystone.policy_file", serveCmd.Flags().Lookup("policy-file"))
	if err != nil {
		panic(err)
	}
}
