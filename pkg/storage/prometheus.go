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
	"github.com/prometheus/client_golang/api/prometheus"
	"github.com/sapcc/maia/pkg/util"
)

type prometheusClient struct {
	client prometheus.Client
}

var prom prometheusClient

// Initialise and return the Prometheus driver
func Prometheus(prometheusAPIURL string) Driver {
	if prom.client == nil {
		config := prometheus.Config{
			Address:   prometheusAPIURL,
			Transport: prometheus.DefaultTransport,
		}
		client, err := prometheus.New(config)
		if err != nil {
			util.LogError("Failed to initialize. Prometheus is not reachable: %s.", prometheusAPIURL)
			return nil
		}
		prom.client = client
	}
	return prom
}

func (prom *prometheusClient) GetMetrics(tenantId string) ([]*Metrics, error) {
	return nil, nil
}
