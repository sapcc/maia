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
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/api/prometheus"
	"github.com/prometheus/common/model"
	"github.com/sapcc/maia/pkg/util"
)

type prometheusClient struct {
	client prometheus.QueryAPI
}

var promCli prometheusClient

// Initialise and return the Prometheus driver
func Prometheus(prometheusAPIURL string) Driver {
	if promCli.client == nil {
		promCli.init(prometheusAPIURL)
	}
	return promCli
}

func (promCli *prometheusClient) init(prometheusAPIURL string) {
	util.LogDebug("Initializing Prometheus Client.")

	config := prometheus.Config{
		Address:   prometheusAPIURL,
		Transport: prometheus.DefaultTransport,
	}
	client, err := prometheus.New(config)
	if err != nil {
		util.LogError("Failed to initialize. Prometheus is not reachable: %s.", prometheusAPIURL)
		panic(err.Error())
	}
	promCli.client = prometheus.NewQueryAPI(client)

}

func (promCli *prometheusClient) ListMetrics(tenantId string) ([]Metric, error) {

	var value model.Value
	var resultVector model.Vector
	var projectQuery = fmt.Sprintf("{project_id='%s'}", tenantId)

	value, err := promCli.client.Query(context.Background(), projectQuery, time.Now())
	if err != nil {
		util.LogError("Could not execute query %s using Prometheus.", projectQuery)
		return nil,err
	}

	resultVector, ok := value.(model.Vector)
	if !ok {
		fmt.Println("Could not get value for query %s from Prometheus due to type mismatch.", projectQuery)
	}

	var metrics []Metric


	for _,v := range resultVector {
		//TODO
		metric := Metric{
				Type: v.String(),
				Metric: v.Metric.String(),
				Value: v.Value.String(),
				Timestamp: v.Timestamp.String(),
				}
		metrics = append(metrics, metric)
	}

	return metrics, nil
}
