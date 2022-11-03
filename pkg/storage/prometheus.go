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
	"io"

	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
)

type prometheusStorageClient struct {
	httpClient       *http.Client
	url, federateURL *url.URL
	customHeaders    map[string]string
}

// Prometheus creates a storage driver for Prometheus/Maia
func Prometheus(prometheusAPIURL string, customHeaders map[string]string) Driver {
	parsedURL, err := url.Parse(prometheusAPIURL)
	if err != nil {
		panic(err)
	}
	result := prometheusStorageClient{
		url:           parsedURL,
		customHeaders: customHeaders,
	}
	result.init()
	return &result
}

func (promCli *prometheusStorageClient) init() {
	if viper.IsSet("maia.proxy") {
		proxyURL, err := url.Parse(viper.GetString("maia.proxy"))
		if err != nil {
			panic(fmt.Errorf("could not set proxy: %s .\n%s", proxyURL, err.Error()))
		} else {
			promCli.httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
			return
		}
	}
	promCli.httpClient = &http.Client{}

	// if federateURL is configured, this will direct /federate requests to another host URL
	if viper.IsSet("maia.federate_url") {
		parsedURL, err := url.Parse(viper.GetString("maia.federate_url"))
		if err != nil {
			panic(err)
		}
		promCli.federateURL = parsedURL
	} else {
		promCli.federateURL = promCli.url
	}
}

func (promCli *prometheusStorageClient) Query(query, time, timeout, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/api/v1/query", map[string]interface{}{"query": query, "time": time, "timeout": timeout})

	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

func (promCli *prometheusStorageClient) QueryRange(query, start, end, step, timeout, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/api/v1/query_range", map[string]interface{}{"query": query, "start": start, "end": end,
		"step": step, "timeout": timeout})

	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

func (promCli *prometheusStorageClient) Series(match []string, start, end, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/api/v1/series", map[string]interface{}{"match[]": match, "start": start, "end": end})

	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

func (promCli *prometheusStorageClient) LabelValues(name, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/api/v1/label/"+name+"/values", map[string]interface{}{})

	res, err := promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})

	return res, err
}

func (promCli *prometheusStorageClient) Federate(selectors []string, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/federate", map[string]interface{}{"match[]": selectors})

	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

func (promCli *prometheusStorageClient) DelegateRequest(request *http.Request) (*http.Response, error) {
	promURL := promCli.mapURL(request.URL)

	return promCli.sendToPrometheus(request.Method, promURL.String(), request.Body, map[string]string{"Accept": request.Header.Get("Accept")})
}

// buildURL is used to build the target URL of a Prometheus call
func (promCli *prometheusStorageClient) buildURL(path string, params map[string]interface{}) url.URL {
	promURL := *promCli.url
	// treat federate special
	if path == "/federate" {
		promURL = *promCli.federateURL
	}

	// change original request to point to our backing Prometheus
	promURL.Path += path
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

	return promURL
}

// mapURL is used to map a Maia URL to Prometheus URL
func (promCli *prometheusStorageClient) mapURL(maiaURL *url.URL) url.URL {
	promURL := *maiaURL

	// change original request to point to our backing Prometheus
	promURL.Host = promCli.url.Host
	promURL.Scheme = promCli.url.Scheme
	promURL.User = promCli.url.User
	promURL.RawQuery = ""

	return promURL
}

// SendToPrometheus takes care of the request wrapping and delivery to Prometheus
func (promCli *prometheusStorageClient) sendToPrometheus(method, promURL string, body io.Reader, headers map[string]string) (*http.Response, error) {
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

	util.LogDebug("Forwarding request to API: %s", promURL)

	resp, err := promCli.httpClient.Do(req)
	if err != nil {
		util.LogError("Request failed.\n%s", err.Error())
		return nil, err
	}
	return resp, nil
}
