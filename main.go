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

package main

import (
	"flag"
	"fmt"
	"os"

	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/databus23/goslo.policy"
	"github.com/sapcc/maia/pkg/api"
	"github.com/sapcc/maia/pkg/cmd"
	"github.com/sapcc/maia/pkg/auth"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
)

var configPath *string

func main() {
	parseCmdlineFlags()

	setDefaultConfig()
	readConfig(configPath)
	keystoneDriver := configuredKeystoneDriver()
	storageDriver := configuredStorageDriver()
	readPolicy()

	// If there are args left over after flag processing, we are a Maia CLI client
	if len(flag.Args()) > 0 {
		cmd.RootCmd.SetArgs(flag.Args())
		cmd.SetDrivers(keystoneDriver, storageDriver)
		if err := cmd.RootCmd.Execute(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else { // otherwise, we are running a Maia API server
		api.Server(keystoneDriver, storageDriver)
	}
}

func parseCmdlineFlags() {
	// Get config file location
	configPath = flag.String("config.file", "maia.conf", "specifies the location of the TOML-format configuration file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
}

func setDefaultConfig() {
	viper.SetDefault("maia.keystone_driver", "keystone")
	viper.SetDefault("maia.storage_driver", "prometheus")
	viper.SetDefault("maia.bind_address", "0.0.0.0:8789")
	viper.SetDefault("maia.prometheus_api_url", "localhost:9090")
}

func readConfig(configPath *string) {
	// Don't read config file if the default config file isn't there,
	//  as we will just fall back to config defaults in that case
	var shouldReadConfig = true
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		shouldReadConfig = *configPath != flag.Lookup("f").DefValue
	}
	// Now we sorted that out, read the config
	if shouldReadConfig {
		viper.SetConfigFile(*configPath)
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		if err != nil { // Handle errors reading the config file
			panic(fmt.Errorf("Fatal error config file: %s", err))
		}
	}

	// Setup environment variable overrides for OpenStack authentication
	for _, osVarName := range cmd.OSVars {
		viper.BindEnv("keystone."+osVarName, "OS_"+strings.ToUpper(osVarName))
	}

}

func configuredKeystoneDriver() keystone.Driver {
	driverName := viper.GetString("maia.keystone_driver")
	switch driverName {
	case "keystone":
		return keystone.Keystone()
	case "mock":
		return keystone.Mock()
	default:
		util.LogFatal("Couldn't match a keystone driver for configured value \"%s\"", driverName)
		return nil
	}
}

func configuredStorageDriver() storage.Driver {
	driverName := viper.GetString("maia.storage_driver")
	switch driverName {
	case "prometheus":
		prometheusAPIURL := viper.GetString("maia.prometheus_api_url")
		if prometheusAPIURL == "" {
			util.LogFatal("Invalid endpoint for prometheus.")
			return nil
		}
		driver := storage.Prometheus(prometheusAPIURL)
		if driver == nil {
			util.LogFatal("Couldn't initialize Prometheus storage driver with given endpoint: \"%s\"", prometheusAPIURL)
			return nil
		}
		util.LogInfo("Using Prometheus storage driver with endpoint: \"%s\"", prometheusAPIURL)

		return driver
	case "mock":
		util.LogInfo("Using Mock storage driver.")
		return storage.Mock()
	default:
		util.LogFatal("Couldn't match a storage driver for configured value \"%s\"", driverName)
		return nil
	}
}

func readPolicy() {
	//load the policy file
	policyEnforcer, err := loadPolicyFile(viper.GetString("maia.PolicyFilePath"))
	if err != nil {
		util.LogFatal(err.Error())
	}
	viper.Set("maia.PolicyEnforcer", policyEnforcer)
}

func loadPolicyFile(path string) (*policy.Enforcer, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules map[string]string
	err = json.Unmarshal(bytes, &rules)
	if err != nil {
		return nil, err
	}
	return policy.NewEnforcer(rules)
}
