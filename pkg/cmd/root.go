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
)

var configFile string
var promURL string

// Version of the Maia server
var version string = "1.0.6"
var showVersion bool

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "maia",
	Short: "OpenStack controlled access to Prometheus metrics",
	Long: `Maia provides multi-tenancy access to Prometheus metrics through an OpenStack service. The maia command
        can be used both as server and as a client to access a Maia service running elsewhere.`,
	Run: func(cmd *cobra.Command, args []string) {
		if showVersion {
			fmt.Println("Maia version", version)
			os.Exit(0)
		} else {
			// If no command is provided, show the help message
			if err := cmd.Help(); err != nil {
				fmt.Fprintf(os.Stderr, "Error showing help: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(-1)
	}
}

func setDefaultConfig() {
	viper.SetDefault("maia.auth_driver", "keystone")
	viper.SetDefault("maia.storage_driver", "prometheus")
	viper.SetDefault("maia.label_value_ttl", "1h")
	viper.SetDefault("keystone.token_cache_time", "900s")
	viper.SetDefault("keystone.roles", "monitoring_viewer,monitoring_admin")
	viper.SetDefault("keystone.default_user_domain_name", "Default")
}

func init() {
	cobra.OnInitialize(func() {
		setDefaultConfig()
	})

	RootCmd.PersistentFlags().StringVarP(&configFile, "config-file", "", "/etc/maia/maia.conf", "Configuration file to use")
	RootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "Print the version number of Maia")
}
