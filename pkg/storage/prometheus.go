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

package storage

import (
	"net/http"

	"net/url"

	"fmt"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
	"io"
)

const prometheusFederateURL = "federate?match[]="

type prometheusStorageClient struct {
	httpClient    *http.Client
	url           string
	customHeaders map[string]string
}

var prometheusCoreHeadersJSON = map[string]string{
	"User-Agent":      "Prometheus/",
	"Accept":          JSON,
	"Accept-Encoding": "gzip",
	"Connection":      "close",
}

var prometheusCoreHeadersText = map[string]string{
	"User-Agent":      "Prometheus/",
	"Accept":          PlainText,
	"Accept-Encoding": "gzip",
	"Connection":      "close",
}

func initPrometheusCoreHeadersJSON() {
	prometheusCoreHeadersJSON["User-Agent"] = "Prometheus/"
	prometheusCoreHeadersJSON["Accept"] = "application/json"
	prometheusCoreHeadersJSON["Connection"] = "close"

}

var prometheusCoreHeadersPBUF = make(map[string]string)

func initPrometheusCoreHeadersPBUF() {
	prometheusCoreHeadersPBUF["User-Agent"] = "Prometheus/"
	prometheusCoreHeadersPBUF["Accept"] = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.7,text/plain;version=0.0.4;q=0.3,*/*;q=0.1"
	prometheusCoreHeadersPBUF["Accept-Encoding"] = "gzip"
	prometheusCoreHeadersPBUF["Connection"] = "close"

}

// Prometheus creates a storage driver for Prometheus
func Prometheus(prometheusAPIURL string) Driver {
	if promCli.client == nil {
		promCli.init(prometheusAPIURL)
	}
	result.init()
	return &result
}

func (promCli *prometheusStorageClient) init() {
	if viper.IsSet("maia.proxy") {
		proxyURL, err := url.Parse(viper.GetString("maia.proxy"))
		if err != nil {
			panic(fmt.Errorf("Could not set proxy: %s .\n%s", proxyURL, err.Error()))
		} else {
			promCli.httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
			return
		}
	}
	promCli.httpClient = &http.Client{}
}

func (promCli *prometheusStorageClient) Query(query, time, timeout string, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("api/v1/query", map[string]interface{}{"query": query, "time": time, "timeout": timeout})

	// TODO: use header from client (not just JSON)
	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

func (promCli *prometheusStorageClient) QueryRange(query, start, end, step, timeout string, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("api/v1/query_range", map[string]interface{}{"query": query, "start": start, "end": end,
		"step": step, "timeout": timeout})

	// TODO: use header from client (not just JSON)
	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

func (promCli *prometheusStorageClient) Series(match []string, start, end string, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("api/v1/series", map[string]interface{}{"match[]": match, "start": start, "end": end})

	// TODO: use header from client (not just JSON)
	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

func (promCli *prometheusStorageClient) LabelValues(name string, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("api/v1/label/"+name+"/values", map[string]interface{}{})

	// TODO: use protobuf with Prometheus client
	res, err := promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})

	return res, err
}

func (promCli *prometheusStorageClient) Federate(selectors []string, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("federate", map[string]interface{}{"match[]": selectors})

	// TODO: use header from client (not just PBUF)
	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

// buildURL is used to build the target URL of a Prometheus call
func (promCli *prometheusStorageClient) buildURL(path string, params map[string]interface{}) url.URL {
	promURL, err := url.Parse(promCli.url)
	if err != nil {
		panic(err)
	}

	initPrometheusCoreHeaders()

	if viper.IsSet("maia.proxy") {
		proxyURL, err := url.Parse(viper.GetString("maia.proxy"))
		if err != nil {
			util.LogError("Could not set proxy: %s .\n%s", proxyURL, err.Error())
			httpCli = http.Client{}
		} else {
			httpCli = http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
		}
	}
	promCli.httpClient = httpCli
}

func (promCli *prometheusStorageClient) Query(query, time, timeout string) (*http.Response, error) {
	promURL := buildURL("api/v1/query", map[string]interface{}{"query": query, "time": time, "timeout": timeout})

	return sendToPrometheus("GET", promURL.String(), nil)
}

func (promCli *prometheusStorageClient) QueryRange(query, start, end, step, timeout string) (*http.Response, error) {
	promURL := buildURL("api/v1/query_range", map[string]interface{}{"query": query, "start": start, "end": end,
		"step": step, "timeout": timeout})

	return sendToPrometheus("GET", promURL.String(), nil)
}

func (promCli *prometheusStorageClient) Series(match []string, start, end string) (*http.Response, error) {
	promURL := buildURL("api/v1/series", map[string]interface{}{"match[]": match, "start": start, "end": end})

	return sendToPrometheus("GET", promURL.String(), nil)
}

func (promCli *prometheusStorageClient) LabelValues(name string) (*http.Response, error) {
	promURL := buildURL("api/v1/series", map[string]interface{}{"match[]": name + "!=\"\""})

	res, err := sendToPrometheus("GET", promURL.String(), nil)

	return res, err
}

// buildURL is used to build the target URL of a Prometheus call
func buildURL(path string, params map[string]interface{}) url.URL {
	promURL, err := url.Parse(promCli.config.Address)
	if err != nil {
		panic(err)
	}

	// change original request to point to our backing Prometheus
	promURL.Path = path
	queryParams := url.Values{}
	for k, v := range params {
		if s, ok := v.(string); ok {
			if s != "" {
				queryParams.Add(k, s)
			}
		} else {
			for _, s := range v.([]string) {
				queryParams.Add(k, s)
			}
		}
	}
	promURL.RawQuery = queryParams.Encode()

	return *promURL
}

// SendToPrometheus takes care of the request wrapping and delivery to Prometheus
func sendToPrometheus(method string, promURL string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, promURL, body)
	if err != nil {
		util.LogError("Could not create request.\n", err.Error())
		return nil, err
	}

	for k, v := range promCli.customHeaders {
		req.Header.Add(k, v)
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	util.LogInfo(promURL)

	resp, err := promCli.httpClient.Do(req)
	if err != nil {
		util.LogError("Request failed.\n%s", err.Error())
		return nil, err
	}
	return resp, nil
}

func (promCli *prometheusStorageClient) ListMetrics(tenantID string) (*http.Response, error) {

	projectQuery := fmt.Sprintf("{project_id='%s'}", tenantID)
	prometheusAPIURL := promCli.config.Address

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s%s", prometheusAPIURL, prometheusFederateURL, projectQuery), nil)
	if err != nil {
		util.LogError("Could not create request.\n", err.Error())
		return nil, err
	}

	for k, v := range prometheusCoreHeaders {
		req.Header.Add(k, v)
	}

	resp, err := promCli.httpClient.Do(req)
	if err != nil {
		util.LogError("Request failed.\n%s", err.Error())
		return nil, err
	}
	return resp, nil
}
