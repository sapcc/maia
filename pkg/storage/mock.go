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

type mock struct{}

// Mock Prometheus driver with static data
func Mock() Driver {
	return mock{}
}

func (m mock) Federate(selectors []string, acceptContentType string) (*http.Response, error) {
	return nil, nil
}

func (m mock) Query(query, time, timeout string, acceptContentType string) (*http.Response, error) {
	return nil, nil
}

func (m mock) QueryRange(query, start, end, step, timeout string, acceptContentType string) (*http.Response, error) {
	return nil, nil
}

func (m mock) Series(match []string, start, end string, acceptContentType string) (*http.Response, error) {
	return nil, nil
}

func (m mock) LabelValues(name string, acceptContentType string) (*http.Response, error) {
	return nil, nil
}
