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
	"errors"
	"fmt"

	"encoding/json"
	"github.com/sapcc/maia/pkg/cmd/auth"
	"github.com/sapcc/maia/pkg/maia"
	"github.com/spf13/cobra"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "list",
	Short: "List all metrics within the current project scope.",
	Long:  `List all metrics within the current project scope.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		token := auth.GetToken(keystoneDriver)
		if !token.Require("metrics:show") {
			return errors.New("You are not authorised to view metrics within the current scope.")
		}

		metric, err := maia.ListMetrics(token.TenantId(), keystoneDriver, storageDriver)
		if err != nil {
			return err
		}
		if metric == nil {
			return fmt.Errorf("Couldn't get metrics for project %s.", token.TenantId())
		}
		json, err := json.MarshalIndent(metric, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s", json)

		return nil
	},
}

func init() {
	RootCmd.AddCommand(getCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}