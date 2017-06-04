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

	"bytes"

	"github.com/gogo/protobuf/proto"
	"github.com/prometheus/client_golang/api/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/sapcc/maia/pkg/util"
	"math"
)

type prometheusClient struct {
	client prometheus.QueryAPI
	config prometheus.Config
}

var promCli prometheusClient

// Initialise and return the Prometheus driver
func Prometheus(prometheusAPIURL string) Driver {
	if promCli.client == nil {
		promCli.init(prometheusAPIURL)
	}
	return &promCli
}

func (promCli *prometheusClient) init(prometheusAPIURL string) {
	util.LogDebug("Initializing Client for Prometheus %s .",prometheusAPIURL)

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

}

func (promCli *prometheusClient) ListMetrics(tenantId string) ([]*Metric, error) {

	var value model.Value
	var resultVector model.Vector
	var projectQuery = "{quantile='0.5'}" //TODO fmt.Sprintf("{project_id='%s'}", tenantId)

	//  /api/v1/query?query={project_id="<projectId>}'
	value, err := promCli.client.Query(context.Background(), projectQuery, time.Now())

	if err != nil {
		util.LogError("Could not execute query %s using Prometheus %s .",projectQuery,promCli.config.Address)
		return nil, err
	}

	resultVector, ok := value.(model.Vector)
	if !ok {
		fmt.Println("Could not get value for query %s from Prometheus due to type mismatch.", projectQuery)
	}

	var metrics []*Metric

	for _, v := range resultVector {
		//TODO: json output
		metric := Metric{
			Type:      v.String(),
			Metric:    v.Metric.String(),
			Value:     v.Value.String(),
			Timestamp: v.Timestamp.String(),
		}
		metrics = append(metrics, &metric)
	}

	//TODO: metrics to text output
	var out bytes.Buffer
	var metricFamily = &dto.MetricFamily{
		Name: proto.String("name"),
		Help: proto.String("help"),
		Metric: []*dto.Metric{
			&dto.Metric{
				Counter: &dto.Counter{
					Value: proto.Float64(math.Inf(-1)),
				},
			},
		},
	}
	expfmt.MetricFamilyToText(&out, metricFamily)

	return metrics, nil
}
