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

var jsonOutput bool
var configFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "maia",
	Short: "OpenStack controlled access to Prometheus metrics",
	Long: `Maia provides multi-tenancy access to Prometheus metrics through an OpenStack service. The maia command
	can be used both as server and as a client to access a Maia service running elsewhere.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func setDefaultConfig() {
	viper.SetDefault("maia.keystone_driver", "keystone")
	viper.SetDefault("maia.storage_driver", "prometheus")
}

func readConfig(configPath string) {
	// Read the maia config file (required for server)
	// That way an OpenStack client environment will not be accidentally used for the "serve" command
	if _, err := os.Stat(configPath); err == nil {
		viper.SetConfigFile(configPath)
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		if err != nil { // Handle errors reading the config file
			panic(fmt.Errorf("Fatal error config file: %s", err))
		}
	}
}

func init() {
	cobra.OnInitialize(func() {
		setDefaultConfig()
		readConfig(configFile)
	})

	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	RootCmd.PersistentFlags().StringVarP(&configFile, "config-file", "c", "/etc/maia/maia.conf", "Configuration file to use")
}
