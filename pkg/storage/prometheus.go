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
	"fmt"

	"net/http"

	"net/url"

	"github.com/prometheus/client_golang/api/prometheus"
	"github.com/sapcc/maia/pkg/util"
	"github.com/spf13/viper"
)

const prometheusFederateUrl = "federate?match[]="

type prometheusStorageClient struct {
	client     prometheus.QueryAPI
	config     prometheus.Config
	httpClient http.Client
}

var promCli prometheusStorageClient

var prometheusCoreHeaders = make(map[string]string)

func initPrometheusCoreHeaders() {
	prometheusCoreHeaders["User-Agent"] = "Prometheus/"
	prometheusCoreHeaders["Accept"] = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.7,text/plain;version=0.0.4;q=0.3,*/*;q=0.1"
	prometheusCoreHeaders["Accept-Encoding"] = "gzip"
	prometheusCoreHeaders["Connection"] = "close"
}

// Initialise and return the Prometheus driver
func Prometheus(prometheusAPIURL string) Driver {
	if promCli.client == nil {
		promCli.init(prometheusAPIURL)
	}
	return &promCli
}

func (promCli *prometheusStorageClient) init(prometheusAPIURL string) {
	var httpCli http.Client

	util.LogDebug("Initializing Client for Prometheus %s .", prometheusAPIURL)

	config := prometheus.Config{
		Address:   prometheusAPIURL,
		Transport: prometheus.DefaultTransport,
	}
	promCli.config = config
	client, err := prometheus.New(config)
	if err != nil {
		util.LogError("Failed to initialize. Prometheus is not reachable: %s.", prometheusAPIURL)
		panic(err.Error())
	}
	promCli.client = prometheus.NewQueryAPI(client)

	initPrometheusCoreHeaders()

	if viper.IsSet("maia.proxy") {
		proxyUrl, err := url.Parse(viper.GetString("maia.proxy"))
		if err != nil {
			util.LogError("Could not set proxy: %s .\n%s", proxyUrl, err.Error())
			httpCli = http.Client{}
		} else {
			httpCli = http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}
		}
	}
	promCli.httpClient = httpCli
}

func (promCli *prometheusStorageClient) ListMetrics(tenantId string) (*http.Response, error) {

	projectQuery := fmt.Sprintf("{project_id='%s'}", tenantId)
	prometheusAPIURL := promCli.config.Address

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s%s", prometheusAPIURL, prometheusFederateUrl, projectQuery), nil)
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
