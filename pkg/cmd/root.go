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

	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"strings"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "maia",
	Short: "Command-line client and API server for OpenStack Prometheus service.",
	Long:  `Command-line client and API server for OpenStack Prometheus service.`,
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

var keystoneDriver keystone.Driver
var storageDriver storage.Driver

// SetDrivers sets which keystone & storage driver to use
func SetDrivers(keystoneParam keystone.Driver, storageParam storage.Driver) {
	keystoneDriver = keystoneParam
	storageDriver = storageParam
}

// OSVars lists the OpenStack configuration/environment variables
// When adding a value here, also add a "RootCmd.PersistentFlags().StringVar" line in cmd/root.go's init()
var OSVars = []string{"username", "password", "auth_url", "user_domain_name", "project_name", "project_domain_name"}

func init() {
	//cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	RootCmd.PersistentFlags().StringVar(&cfgFile, "os-keystone-url", "", "OpenStack Authentication URL")
	RootCmd.PersistentFlags().StringVar(&cfgFile, "os-username", "", "OpenStack Username")
	RootCmd.PersistentFlags().StringVar(&cfgFile, "os-password", "", "OpenStack Password")
	RootCmd.PersistentFlags().StringVar(&cfgFile, "os-user-domain-name", "", "OpenStack User's domain name")
	RootCmd.PersistentFlags().StringVar(&cfgFile, "os-project-name", "", "OpenStack Project name to scope to")
	RootCmd.PersistentFlags().StringVar(&cfgFile, "os-project-domain-name", "", "OpenStack Project's domain name")

	// Setup command-line flags for OpenStack authentication
	for _, val := range OSVars {
		flags := RootCmd.PersistentFlags()
		lookup := "os-" + strings.Replace(val, "_", "-", -1)
		pflag := flags.Lookup(lookup)
		viper.BindPFlag("keystone."+val, pflag)
	}
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
