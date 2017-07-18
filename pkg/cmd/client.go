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
	"encoding/json"
	"fmt"
	"github.com/databus23/goslo.policy"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/prometheus/common/model"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/template"
	"time"
)

var maiaURL string
var selector string
var auth tokens.AuthOptions
var scopedDomain string
var outputFormat string
var jsonTemplate string
var columns string
var separator string
var starttime, endtime, timestamp string
var timeout, stepsize time.Duration

// recoverAll is used to turn panics into error output
// we use panics here for any errors
func recoverAll() {
	if r := recover(); r != nil {
		fmt.Fprintln(os.Stderr, r)
	}
}

func authenticate() *policy.Context {
	if scopedDomain != "" {
		auth.Scope.DomainName = scopedDomain
	}
	if auth.TokenID == "" && maiaURL != "" {
		if auth.Username == "" || auth.Password == "" {
			panic(fmt.Errorf("You must at least specify --os-username and --os-password"))
		}
	}
	context, err := keystone.NewKeystoneDriver().Authenticate(&auth, false)
	if err == nil {
		return context
	}
	panic(err)
}

func prometheus(context *policy.Context) storage.Driver {
	if maiaURL != "" {
		return storage.NewPrometheusDriver(maiaURL, map[string]string{"X-Auth-Token": context.Auth["token"]})
	} else if promURL != "" {
		return storage.NewPrometheusDriver(promURL, map[string]string{"X-Auth-Token": context.Auth["token"]})
	} else {
		panic(fmt.Errorf("Either --maia-url or --prometheus-url need to be specified (or MAIA_SERVER_URL resp. MAIA_PROMETHEUS_URL)"))
	}
}

func outputTemplate(columns []string) string {
	str := "{{ ." + strings.Join(columns, separator+".") + "}}"
	return str
}

func printValues(resp *http.Response) {
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Server responsed with error code %d: %s", resp.StatusCode, err.Error())
	} else {
		contentType := resp.Header.Get("Content-Type")
		if contentType == storage.JSON {
			if outputFormat == "json" && columns == "" {
				fmt.Print(string(body))
			} else {
				var jsonResponse struct {
					Value []string `json:"data,omitempty"`
				}
				if err := json.Unmarshal([]byte(body), &jsonResponse); err != nil {
					panic(err)
				}

				for _, value := range jsonResponse.Value {
					fmt.Println(value)
				}
			}
		} else if strings.HasPrefix(contentType, "text/plain") {
			if outputFormat == "" || outputFormat == "values" {
				fmt.Print(string(body))
			} else {
				panic(fmt.Errorf("Unsupported --format value for this command: %s", outputFormat))
			}
		} else {
			panic(fmt.Errorf("Unsupported response type from server: %s", contentType))
		}
	}
}

func printTable(resp *http.Response) {
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Server responsed with error code %d: %s", resp.StatusCode, err.Error())
	} else {
		contentType := resp.Header.Get("Content-Type")
		if contentType == storage.JSON {
			// JSON is not preprocessed
			if outputFormat == "json" {
				fmt.Print(string(body))
				return
			} else if outputFormat == "table" || outputFormat == "value" || outputFormat == "" {

				// unmarshal
				var jsonResponse struct {
					Table []model.LabelSet `json:"data,omitempty"`
				}
				if err := json.Unmarshal([]byte(body), &jsonResponse); err != nil {
					panic(err)
				}

				// determine relevant columns
				var allColumns []string
				if columns == "" {
					allColumns = extractSeriesColumns(jsonResponse.Table)
				} else {
					allColumns = strings.Split(columns, ",")
				}

				printHeader(allColumns)

				// Print relevant columns in sorted order
				for _, series := range jsonResponse.Table {
					row := map[string]string{}
					for k, v := range series {
						row[string(k)] = string(v)
					}
					printRow(allColumns, row)
				}
			} else {
				panic(fmt.Errorf("Unsupported --format value for this command: %s", outputFormat))
			}
		} else if contentType == storage.PlainText {
			// This affects /federate aka. metrics only. There is no point in filtering this output
			fmt.Print(string(body))
		} else {
			panic(fmt.Errorf("Unsupported response type from server: %s", contentType))
		}
	}
}

func buildColumnSet(promResult model.Value) map[string]bool {
	result := map[string]bool{}
	if columns != "" {
		for _, c := range strings.Split(columns, ",") {
			result[c] = true
		}
	} else if vector, ok := promResult.(model.Vector); ok {
		for _, el := range vector {
			collectKeys(result, model.LabelSet(el.Metric))
		}
	} else if matrix, ok := promResult.(model.Matrix); ok {
		for _, el := range matrix {
			collectKeys(result, model.LabelSet(el.Metric))
		}
	}
	return result
}

func printHeader(allColumns []string) {
	if outputFormat != "value" {
		for i, field := range allColumns {
			if i > 0 {
				fmt.Print(separator)
			}
			fmt.Print(field)
		}
		fmt.Println()
	}
}

func extractSeriesColumns(table []model.LabelSet) []string {
	// print all columns
	set := map[string]bool{}
	for _, rec := range table {
		collectKeys(set, rec)
	}
	return makeColumns(set)
}

func collectKeys(collector map[string]bool, input model.LabelSet) {
	// print all columns
	for label := range input {
		collector[string(label)] = true
	}
}

func makeColumns(collector map[string]bool) []string {
	// print all columns
	allColumns := []string{}
	for k := range collector {
		allColumns = append(allColumns, k)
	}
	sort.Strings(allColumns)
	return allColumns
}

func printRow(allColumns []string, rec map[string]string) {
	for i, field := range allColumns {
		if i > 0 {
			fmt.Print(separator)
		}
		if v, ok := rec[field]; ok {
			fmt.Print(v)
		}
	}
	fmt.Println()
}

func printTemplate(body []byte, tpl string) {
	t := template.Must(template.New("").Parse(tpl))
	m := map[string]interface{}{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		panic(err)
	}
	if err := t.Execute(os.Stdout, m); err != nil {
		panic(err)
	}
}

// timeColumnFromTS creates a table column for a timestamp; it rounds it off to the step-size
func timeColumnFromTS(ts time.Time) string {
	return ts.Truncate(stepsize).Format(time.RFC3339)
}

func printQueryResultAsTable(body []byte) {
	var queryResponse storage.QueryResponse
	err := json.Unmarshal(body, &queryResponse)
	if err != nil {
		panic(err)
	}

	valueObject := model.Value(queryResponse.Data.Value)

	rows := []map[string]string{}
	var allColumns []string

	switch valueObject.Type() {
	case model.ValMatrix:
		matrix := valueObject.(model.Matrix)
		tsSet := map[string]bool{}
		// if no columns have been specified by user then collect them all
		set := buildColumnSet(matrix)
		for _, el := range matrix {
			columnValues := map[string]string{}
			for labelKey, labelValue := range el.Metric {
				columnValues[string(labelKey)] = string(labelValue)
			}
			for _, value := range el.Values {
				s := timeColumnFromTS(value.Timestamp.Time())
				tsSet[s] = true
				columnValues[s] = value.Value.String()
			}
			rows = append(rows, columnValues)
		}
		allColumns = append(makeColumns(set), makeColumns(tsSet)...)
	case model.ValVector:
		matrix := valueObject.(model.Vector)
		set := buildColumnSet(matrix)
		for _, el := range matrix {
			collectKeys(set, model.LabelSet(el.Metric))
			columnValues := map[string]string{}
			columnValues["Timestamp"] = el.Timestamp.Time().Format(time.RFC3339Nano)
			columnValues["Value"] = el.Value.String()
			rows = append(rows, columnValues)
		}
		allColumns = append(makeColumns(set), []string{"Timestamp", "Value"}...)
	case model.ValScalar:
		scalarValue := valueObject.(*model.Scalar)
		allColumns = []string{"Timestamp", "Value"}
		rows = []map[string]string{{"Timestamp": scalarValue.Timestamp.Time().Format(time.RFC3339Nano), "Value": scalarValue.String()}}
	}
	printHeader(allColumns)
	for _, row := range rows {
		printRow(allColumns, row)
	}
}

func printQueryResponse(resp *http.Response) {
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Server responsed with error code %d: %s", resp.StatusCode, err.Error())
	} else {
		contentType := resp.Header.Get("Content-Type")
		if contentType == storage.JSON {
			if outputFormat == "json" || outputFormat == "" {
				fmt.Print(string(body))
			} else if outputFormat == "template" {
				if jsonTemplate == "" {
					panic(fmt.Errorf("Missing --template parameter"))
				}
				printTemplate(body, jsonTemplate)
			} else if outputFormat == "table" {
				printQueryResultAsTable(body)
			} else {
				panic(fmt.Errorf("Unsupported --format value for this command: %s", outputFormat))
			}
		} else {
			panic(fmt.Errorf("Unsupported response type from server: %s", contentType))
		}
	}
}

var snapshotCmd = &cobra.Command{
	Use:   "snapshot [ --selector <vector-selector> ]",
	Short: "Get a snapshot of the actual metric values for a project/domain.",
	Long:  "Displays the current values of all metric series. The series can filtered using vector-selectors (label constraints).",
	RunE: func(cmd *cobra.Command, args []string) (ret error) {
		// transform panics with error params into errors
		defer recoverAll()

		context := authenticate()
		// pass the keystone token to Maia and ensure that the result is text
		prometheus := prometheus(context)

		var resp *http.Response
		resp, err := prometheus.Federate([]string{"{" + selector + "}"}, storage.PlainText)
		if err != nil {
			panic(err)
		}

		printValues(resp)

		return nil
	},
}

var seriesCmd = &cobra.Command{
	Use:   "series [ --selector <vector-selector> ]",
	Short: "List measurement series for project/domain.",
	Long:  "Lists all metric series. The series can filtered using vector-selectors (label constraints).",
	RunE: func(cmd *cobra.Command, args []string) (ret error) {
		// transform panics with error params into errors
		defer recoverAll()

		context := authenticate()
		// pass the keystone token to Maia and ensure that the result is text
		prometheus := prometheus(context)

		var resp *http.Response
		resp, err := prometheus.Series([]string{"{" + selector + "}"}, starttime, endtime, storage.PlainText)
		if err != nil {
			panic(err)
		}

		printTable(resp)

		return nil
	},
}

func labelValues(labelName string) (ret error) {
	// transform panics with error params into errors
	defer recoverAll()

	context := authenticate()
	// pass the keystone token to Maia and ensure that the result is text
	prometheus := prometheus(context)

	var resp *http.Response
	resp, err := prometheus.LabelValues(labelName, storage.JSON)
	if err != nil {
		panic(err)
	}

	printValues(resp)

	return nil
}

var labelValuesCmd = &cobra.Command{
	Use:   "label-values <label-name>",
	Short: "Get values for given label name.",
	Long:  "Obtains the possible values for a given label name (key) taking into account all series that are currently stored.",
	RunE: func(cmd *cobra.Command, args []string) (ret error) {
		// transform panics with error params into errors
		defer recoverAll()

		// check parameters
		if len(args) < 1 {
			return fmt.Errorf("missing argument: label-name")
		}
		return labelValues(args[0])
	},
}

var metricNamesCmd = &cobra.Command{
	Use:   "metric-names",
	Short: "Get list of metric names.",
	Long:  "Obtains a list of metric names taking into account all series that are currently stored.",
	RunE: func(cmd *cobra.Command, args []string) (ret error) {
		// transform panics with error params into errors
		defer recoverAll()

		return labelValues("__name__")
	},
}

var queryCmd = &cobra.Command{
	Use:   "query <PromQL query> [ --timestamp | --start <starttime> --end <endtime> --step <duration> ] [ --timeout <duration> ]",
	Short: "Perform a PromQL query",
	Long:  "Performs a PromQL query against the metrics available for the project/domain in scope",
	RunE: func(cmd *cobra.Command, args []string) (ret error) {
		// transform panics with error params into errors
		defer recoverAll()

		// check parameters
		if len(args) < 1 {
			return fmt.Errorf("missing argument: PromQL query")
		}
		query := args[0]

		var timeoutStr, stepStr string
		if timeout > 0 {
			// workaround parsing issues
			timeoutStr = fmt.Sprintf("%ds", int(timeout.Seconds()))
		} else {
			timeoutStr = ""
		}
		if stepsize > 0 {
			stepStr = fmt.Sprintf("%ds", int(stepsize.Seconds()))
		} else {
			stepStr = ""
		}

		// authenticate and connect
		context := authenticate()
		prometheus := prometheus(context)

		// perform (range-)query
		var resp *http.Response
		var err error
		if starttime != "" && endtime != "" && stepsize != 0 {
			resp, err = prometheus.QueryRange(query, starttime, endtime, stepStr, timeoutStr, storage.JSON)
		} else {
			resp, err = prometheus.Query(query, timestamp, timeoutStr, storage.JSON)
		}

		if err != nil {
			panic(err)
		}

		printQueryResponse(resp)

		return nil
	},
}

func init() {

	RootCmd.AddCommand(snapshotCmd)
	RootCmd.AddCommand(queryCmd)
	RootCmd.AddCommand(seriesCmd)
	RootCmd.AddCommand(labelValuesCmd)
	RootCmd.AddCommand(metricNamesCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// snapshotCmd.PersistentFlags().String("foo", "", "A help for foo")

	snapshotCmd.Flags().StringVarP(&selector, "selector", "l", "", "Prometheus label-selector to restrict the amount of metrics")
	addClientFlags(snapshotCmd)

	queryCmd.Flags().StringVar(&starttime, "start", "", "Range query: Start timestamp (RFC3339 or Unix format; default:earliest)")
	queryCmd.Flags().StringVar(&endtime, "end", "", "Range query: End timestamp (RFC3339 or Unix format; default: latest)")
	queryCmd.Flags().StringVar(&timestamp, "timestamp", "", "Timestamp of measurement (RFC3339 or Unix format; default: latest)")
	queryCmd.Flags().DurationVarP(&timeout, "timeout", "", 0, "Optional: Timeout for query (e.g. 10m; default: server setting)")
	queryCmd.Flags().DurationVarP(&stepsize, "step", "", 0, "Optional: Step size for range query (e.g. 30s)")
	addClientFlags(queryCmd)

	addClientFlags(labelValuesCmd)

	addClientFlags(metricNamesCmd)

	seriesCmd.Flags().StringVarP(&selector, "selector", "l", "", "Prometheus label-selector to restrict the amount of metrics")
	seriesCmd.Flags().StringVar(&starttime, "start", "", "Start timestamp (RFC3339 or Unix format; default:earliest)")
	seriesCmd.Flags().StringVar(&endtime, "end", "", "End timestamp (RFC3339 or Unix format; default: latest)")
	addClientFlags(seriesCmd)
}

func addClientFlags(cmd *cobra.Command) {
	// pass OpenStack auth. information via global top-level parameters or environment variables
	// it is used by the "serve" command as service user, otherwise to authenticate the client
	cmd.PersistentFlags().StringVar(&auth.IdentityEndpoint, "os-auth-url", os.Getenv("OS_AUTH_URL"), "OpenStack Authentication URL")
	viper.BindPFlag("keystone.auth_url", cmd.PersistentFlags().Lookup("os-auth-url"))

	cmd.PersistentFlags().StringVar(&auth.Username, "os-username", os.Getenv("OS_USERNAME"), "OpenStack Username")
	cmd.PersistentFlags().StringVar(&auth.Password, "os-password", os.Getenv("OS_PASSWORD"), "OpenStack Password")
	cmd.PersistentFlags().StringVar(&auth.DomainName, "os-user-domain-name", os.Getenv("OS_USER_DOMAIN_NAME"), "OpenStack User's domain name")
	cmd.PersistentFlags().StringVar(&auth.DomainID, "os-user-domain-id", os.Getenv("OS_USER_DOMAIN_ID"), "OpenStack User's domain ID")
	cmd.PersistentFlags().StringVar(&auth.Scope.ProjectName, "os-project-name", os.Getenv("OS_PROJECT_NAME"), "OpenStack Project name to scope to")
	cmd.PersistentFlags().StringVar(&auth.Scope.DomainName, "os-project-domain-name", os.Getenv("OS_PROJECT_DOMAIN_NAME"), "OpenStack Project's domain name")
	cmd.PersistentFlags().StringVar(&scopedDomain, "os-domain-name", os.Getenv("OS_DOMAIN_NAME"), "OpenStack domain name to scope to")
	cmd.PersistentFlags().StringVar(&auth.Scope.DomainID, "os-domain-id", os.Getenv("OS_DOMAIN_ID"), "OpenStack domain ID to scope to")
	cmd.PersistentFlags().StringVar(&auth.TokenID, "os-token", os.Getenv("OS_TOKEN"), "OpenStack keystone token")

	cmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "", "Specify output format: table, json, template or value")
	cmd.PersistentFlags().StringVarP(&columns, "columns", "c", "", "Specify the columns to print (comma-separated; only when --format value is set)")
	cmd.PersistentFlags().StringVar(&separator, "separator", " ", "Separate different columns with this string (only when --columns value is set; default <space>)")
	cmd.PersistentFlags().StringVar(&jsonTemplate, "template", "", "Go-template to define a custom output format based on the JSON response (only when --format=template)")

	cmd.Flags().StringVar(&maiaURL, "maia-url", os.Getenv("MAIA_SERVICE_URL"), "URL of the target Maia service (override OpenStack service catalog)")
	cmd.PersistentFlags().StringVar(&promURL, "prometheus-url", os.Getenv("MAIA_PROMETHEUS_URL"), "URL of the Prometheus server backing Maia (MAIA_PROMETHEUS_URL)")
	viper.BindPFlag("maia.prometheus_url", cmd.PersistentFlags().Lookup("prometheus-url"))
}
