// SPDX-FileCopyrightText: 2017 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configFile string
var promURL string
var version = "1.0.7"

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "maia",
	Short: "OpenStack controlled access to Prometheus metrics",
	Long: `Maia provides multi-tenancy access to Prometheus metrics through an OpenStack service. The maia command
	can be used both as server and as a client to access a Maia service running elsewhere.`,
	Run: func(cmd *cobra.Command, args []string) {
		if cmd.Flags().Lookup("version").Changed {
			fmt.Println("Maia Version:", version)
			os.Exit(0)
		}
	},
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	ExecuteWithContext(context.Background())
}

// ExecuteWithContext is similar to Execute but takes a context
func ExecuteWithContext(ctx context.Context) {
	// Add the context to the root command
	RootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		// You can use the context here if needed
		cmd.SetContext(ctx)
	}

	if err := RootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
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
	RootCmd.PersistentFlags().Bool("version", false, "Print version information and quit")
}
