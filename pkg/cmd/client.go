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
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/prometheus/common/model"
	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/util"
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

const (
	timestampKey = "__timestamp__"
	valueKey     = "__value__"
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

var keystoneDriver keystone.Driver
var storageDriver storage.Driver
var tzLocation = time.Local

// recoverAll is used to turn panics into error output
// we use panics here for any errors
func recoverAll() {
	if r := recover(); r != nil {
		fmt.Fprintln(os.Stderr, r)
	}
}

func fetchToken() {
	if scopedDomain != "" {
		auth.Scope.DomainName = scopedDomain
	}
	// authenticate calls to Maia
	if auth.TokenID != "" && maiaURL != "" {
		return
	}
	if auth.Password == "$OS_PASSWORD" {
		auth.Password = os.Getenv("OS_PASSWORD")
	}
	if (auth.Username == "" && auth.UserID == "") || auth.Password == "" {
		panic(fmt.Errorf("You must at least specify --os-username / --os-user-id and --os-password"))
	}
	context, url, err := keystoneInstance().Authenticate(&auth)
	if err != nil {
		panic(err)
	}
	auth.TokenID = context.Auth["token"]
	if maiaURL == "" {
		maiaURL = url
	}
}

func storageInstance() storage.Driver {
	if storageDriver == nil {
		if promURL != "" {
			storageDriver = storage.NewPrometheusDriver(promURL, map[string]string{})
		} else if auth.IdentityEndpoint != "" {
			// authenticate and set maiaURL if missing
			fetchToken()
			storageDriver = storage.NewPrometheusDriver(maiaURL, map[string]string{"X-Auth-Token": auth.TokenID})
		} else if promURL != "" {
		} else {
			panic(fmt.Errorf("Either --maia-url or --storageInstance-url need to be specified (or MAIA_URL resp. MAIA_PROMETHEUS_URL)"))
		}
	}

	return storageDriver
}

func keystoneInstance() keystone.Driver {
	if keystoneDriver == nil {
		setKeystoneInstance(keystone.NewKeystoneDriver())
	}
	return keystoneDriver
}

func printValues(resp *http.Response) {
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Errorf("Server responsed with error code %d: %s", resp.StatusCode, err.Error()))
	} else {
		contentType := resp.Header.Get("Content-Type")
		if contentType == storage.JSON {
			if strings.EqualFold(outputFormat, "json") {
				fmt.Print(string(body))
			} else if strings.EqualFold(outputFormat, "value") {
				var jsonResponse struct {
					Value []string `json:"data,omitempty"`
				}
				if err := json.Unmarshal([]byte(body), &jsonResponse); err != nil {
					panic(err)
				}

				for _, value := range jsonResponse.Value {
					fmt.Println(value)
				}
			} else {
				panic(fmt.Errorf("Unsupported --format value for this command: %s", outputFormat))
			}
		} else if strings.HasPrefix(contentType, "text/plain") {
			if strings.EqualFold(outputFormat, "value") {
				fmt.Print(string(body))
			} else {
				panic(fmt.Errorf("Unsupported --format value for this command: %s", outputFormat))
			}
		} else {
			util.LogError("Response body: %s", string(body))
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
			if strings.EqualFold(outputFormat, "json") {
				fmt.Print(string(body))
				return
			} else if strings.EqualFold(outputFormat, "table") || strings.EqualFold(outputFormat, "value") {

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
		} else if strings.HasPrefix(contentType, "text/plain") {
			// This affects /federate aka. metrics only. There is no point in filtering this output
			fmt.Print(string(body))
		} else {
			util.LogWarning("Response body: %s", string(body))
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
	if !strings.EqualFold(outputFormat, "value") {
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
	return ts.Truncate(stepsize).In(tzLocation).Format(time.RFC3339)
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
			columnValues[timestampKey] = el.Timestamp.Time().In(tzLocation).Format(time.RFC3339Nano)
			columnValues[valueKey] = el.Value.String()
			for labelKey, labelValue := range el.Metric {
				columnValues[string(labelKey)] = string(labelValue)
			}
			rows = append(rows, columnValues)
		}
		allColumns = append(makeColumns(set), []string{timestampKey, valueKey}...)
	case model.ValScalar:
		scalarValue := valueObject.(*model.Scalar)
		allColumns = []string{timestampKey, valueKey}
		rows = []map[string]string{{timestampKey: scalarValue.Timestamp.Time().In(tzLocation).Format(time.RFC3339Nano), valueKey: scalarValue.String()}}
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
			if strings.EqualFold(outputFormat, "json") {
				fmt.Print(string(body))
			} else if strings.EqualFold(outputFormat, "template") {
				if jsonTemplate == "" {
					panic(fmt.Errorf("Missing --template parameter"))
				}
				printTemplate(body, jsonTemplate)
			} else if strings.EqualFold(outputFormat, "table") {
				printQueryResultAsTable(body)
			} else {
				panic(fmt.Errorf("Unsupported --format value for this command: %s", outputFormat))
			}
		} else {
			util.LogWarning("Response body: %s", string(body))
			panic(fmt.Errorf("Unsupported response type from server: %s", contentType))
		}
	}
}

// Snapshot is just public because unit testing frameworks complains otherwise
func Snapshot(cmd *cobra.Command, args []string) (ret error) {
	// transform panics with error params into errors
	defer recoverAll()

	setDefaultOutputFormat("value")

	prometheus := storageInstance()

	var resp *http.Response
	resp, err := prometheus.Federate([]string{"{" + selector + "}"}, storage.PlainText)
	checkResponse(err, resp)

	printValues(resp)

	return nil
}

// LabelValues is just public because unit testing frameworks complains otherwise
func LabelValues(cmd *cobra.Command, args []string) (ret error) {
	// transform panics with error params into errors
	defer recoverAll()

	setDefaultOutputFormat("value")

	// check parameters
	if len(args) < 1 {
		return fmt.Errorf("missing argument: label-name")
	}
	labelName := args[0]

	prometheus := storageInstance()

	var resp *http.Response
	resp, err := prometheus.LabelValues(labelName, storage.JSON)
	checkResponse(err, resp)

	printValues(resp)

	return nil
}

// Series is just public because unit testing frameworks complains otherwise
func Series(cmd *cobra.Command, args []string) (ret error) {
	// transform panics with error params into errors
	defer recoverAll()

	setDefaultOutputFormat("table")

	// pass the keystone token to Maia and ensure that the result is text
	prometheus := storageInstance()

	var resp *http.Response
	resp, err := prometheus.Series([]string{"{" + selector + "}"}, starttime, endtime, storage.JSON)
	checkResponse(err, resp)

	printTable(resp)

	return nil
}

// MetricNames is just public because unit testing frameworks complains otherwise
func MetricNames(cmd *cobra.Command, args []string) (ret error) {
	// transform panics with error params into errors
	defer recoverAll()

	setDefaultOutputFormat("value")

	return LabelValues(cmd, []string{"__name__"})
}

// Query is just public because unit testing frameworks complains otherwise
func Query(cmd *cobra.Command, args []string) (ret error) {
	// transform panics with error params into errors
	defer recoverAll()

	setDefaultOutputFormat("json")

	// check parameters
	if len(args) < 1 {
		return fmt.Errorf("missing argument: PromQL Query")
	}
	queryExpr := args[0]

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

	prometheus := storageInstance()

	// perform (range-)Query
	var resp *http.Response
	var err error
	if starttime != "" && endtime != "" && stepsize != 0 {
		resp, err = prometheus.QueryRange(queryExpr, starttime, endtime, stepStr, timeoutStr, storage.JSON)
	} else {
		resp, err = prometheus.Query(queryExpr, timestamp, timeoutStr, storage.JSON)
	}

	checkResponse(err, resp)

	printQueryResponse(resp)

	return nil
}

func setDefaultOutputFormat(format string) {
	if outputFormat == "" {
		outputFormat = format
	}
}

// checkHttpStatus checks whether the response is 200 and panics with an appropriate error otherwise
func checkResponse(err error, resp *http.Response) {
	if err != nil {
		panic(err)
	} else if resp.StatusCode != http.StatusOK {
		panic(fmt.Errorf("Server failed with status: %s (%d)", string(resp.Status), resp.StatusCode))
	}
}

var snapshotCmd = &cobra.Command{
	Use:   "snapshot [ --selector <vector-selector> ]",
	Short: "Get a Snapshot of the actual metric values for a project/domain.",
	Long:  "Displays the current values of all metric Series. The Series can filtered using vector-selectors (label constraints).",
	RunE:  Snapshot,
}

var seriesCmd = &cobra.Command{
	Use:   "series [ --selector <vector-selector> ] [ --start <starttime> --end <endtime> ]",
	Short: "List measurement Series for project/domain.",
	Long:  "Lists all metric Series. The Series can filtered using vector-selectors (label constraints).",
	RunE:  Series,
}

var labelValuesCmd = &cobra.Command{
	Use:   "label-values <label-name>",
	Short: "Get values for given label name.",
	Long:  "Obtains the possible values for a given label name (key) taking into account all Series that are currently stored.",
	RunE:  LabelValues,
}

var metricNamesCmd = &cobra.Command{
	Use:   "metric-names",
	Short: "Get list of metric names.",
	Long:  "Obtains a list of metric names taking into account all Series that are currently stored.",
	RunE:  MetricNames,
}

var queryCmd = &cobra.Command{
	Use:   "query <PromQL Query> [ --timestamp | --start <starttime> --end <endtime> --step <duration> ] [ --timeout <duration> ]",
	Short: "Perform a PromQL Query",
	Long:  "Performs a PromQL Query against the metrics available for the project/domain in scope",
	RunE:  Query,
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

	// pass OpenStack auth. information via global top-level parameters or environment variables
	// it is used by the "serve" command as service user, otherwise to authenticate the client
	RootCmd.PersistentFlags().StringVar(&auth.IdentityEndpoint, "os-auth-url", os.Getenv("OS_AUTH_URL"), "OpenStack Authentication URL")
	viper.BindPFlag("keystone.auth_url", RootCmd.PersistentFlags().Lookup("os-auth-url"))

	RootCmd.PersistentFlags().StringVar(&auth.Username, "os-username", os.Getenv("OS_USERNAME"), "OpenStack Username")
	RootCmd.PersistentFlags().StringVar(&auth.UserID, "os-user-id", os.Getenv("OS_USER_ID"), "OpenStack Username")
	RootCmd.PersistentFlags().StringVar(&auth.Password, "os-password", "$OS_PASSWORD", "OpenStack Password")
	RootCmd.PersistentFlags().StringVar(&auth.DomainName, "os-user-domain-name", os.Getenv("OS_USER_DOMAIN_NAME"), "OpenStack User's domain name")
	RootCmd.PersistentFlags().StringVar(&auth.DomainID, "os-user-domain-id", os.Getenv("OS_USER_DOMAIN_ID"), "OpenStack User's domain ID")
	RootCmd.PersistentFlags().StringVar(&auth.Scope.ProjectName, "os-project-name", os.Getenv("OS_PROJECT_NAME"), "OpenStack Project name to scope to")
	RootCmd.PersistentFlags().StringVar(&auth.Scope.ProjectID, "os-project-id", os.Getenv("OS_PROJECT_ID"), "OpenStack Project ID to scope to")
	RootCmd.PersistentFlags().StringVar(&auth.Scope.DomainName, "os-project-domain-name", os.Getenv("OS_PROJECT_DOMAIN_NAME"), "OpenStack Project's domain name")
	RootCmd.PersistentFlags().StringVar(&scopedDomain, "os-domain-name", os.Getenv("OS_DOMAIN_NAME"), "OpenStack domain name to scope to")
	RootCmd.PersistentFlags().StringVar(&auth.Scope.DomainID, "os-domain-id", os.Getenv("OS_DOMAIN_ID"), "OpenStack domain ID to scope to")
	RootCmd.PersistentFlags().StringVar(&auth.TokenID, "os-token", os.Getenv("OS_TOKEN"), "OpenStack keystone token")

	RootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "", "Specify output format: table, json, template or value")
	RootCmd.PersistentFlags().StringVarP(&columns, "columns", "c", "", "Specify the columns to print (comma-separated; only when --format value is set)")
	RootCmd.PersistentFlags().StringVar(&separator, "separator", " ", "Separate different columns with this string (only when --columns value is set; default <space>)")
	RootCmd.PersistentFlags().StringVar(&jsonTemplate, "template", "", "Go-template to define a custom output format based on the JSON response (only when --format=template)")

	RootCmd.PersistentFlags().StringVar(&maiaURL, "maia-url", os.Getenv("MAIA_URL"), "URL of the target Maia service (override OpenStack service catalog)")
	RootCmd.PersistentFlags().StringVar(&promURL, "prometheus-url", os.Getenv("MAIA_PROMETHEUS_URL"), "URL of the Prometheus server backing Maia (MAIA_PROMETHEUS_URL)")
	viper.BindPFlag("maia.prometheus_url", RootCmd.PersistentFlags().Lookup("prometheus-url"))

	snapshotCmd.Flags().StringVarP(&selector, "selector", "l", "", "Prometheus label-selector to restrict the amount of metrics")

	queryCmd.Flags().StringVar(&starttime, "start", "", "Range Query: Start timestamp (RFC3339 or Unix format; default:earliest)")
	queryCmd.Flags().StringVar(&endtime, "end", "", "Range Query: End timestamp (RFC3339 or Unix format; default: latest)")
	queryCmd.Flags().StringVar(&timestamp, "timestamp", "", "Timestamp of measurement (RFC3339 or Unix format; default: latest)")
	queryCmd.Flags().DurationVarP(&timeout, "timeout", "", 0, "Optional: Timeout for Query (e.g. 10m; default: server setting)")
	queryCmd.Flags().DurationVarP(&stepsize, "step", "", 0, "Optional: Step size for range Query (e.g. 30s)")

	seriesCmd.Flags().StringVarP(&selector, "selector", "l", "", "Prometheus label-selector to restrict the amount of metrics")
	seriesCmd.Flags().StringVar(&starttime, "start", "", "Start timestamp (RFC3339 or Unix format; default:earliest)")
	seriesCmd.Flags().StringVar(&endtime, "end", "", "End timestamp (RFC3339 or Unix format; default: latest)")
}

func setKeystoneInstance(keystone keystone.Driver) {
	keystoneDriver = keystone
}

func setStorageInstance(storage storage.Driver) {
	storageDriver = storage
}
