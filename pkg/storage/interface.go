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
)

// Driver is an interface that wraps the underlying event storage mechanism.
// Because it is an interface, the real implementation can be mocked away in unit tests.
// For pragmatic reasons the HTTP response from the underlying storage service is passed
// on unchanged. For most API operations, Maia does not have to transform the response and that way
// we can avoid an entire in-memory unmarshal-marshal cycle.
type Driver interface {
	/********** requests to Prometheus **********/
	ListMetrics(tenantId string) (*http.Response, error)

	Query(query, time, timeout string) (*http.Response, error)
	QueryRange(query, start, end, step, timeout string) (*http.Response, error)
	Series(match []string, start, end string) (*http.Response, error)
	LabelValues(name string) (*http.Response, error)
}
