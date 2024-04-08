// Copyright 2024 SAP SE
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package test

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"go.uber.org/mock/gomock"
)

// HTTPRequestMatcher matches against http.Request parameters
// Optionally it can check the header-contents and inject new header-fields as a side-effect
type HTTPRequestMatcher struct {
	gomock.Matcher
	// ExpectHeader contains the required header fields and a regexp pattern to match
	ExpectHeader map[string]string
	// InjectHeader contains the new fields to be injected
	InjectHeader map[string]string
}

// Matches checks for expected headers (precondition) and injects additional ones (postcondition)
func (m HTTPRequestMatcher) Matches(x interface{}) bool {
	httpReq, ok := x.(*http.Request)
	if ok && httpReq != nil {
		for k, v := range m.ExpectHeader {
			if match, err := regexp.MatchString(v, httpReq.Header.Get(k)); !match || err != nil {
				return false
			}
		}
		for k, v := range m.InjectHeader {
			httpReq.Header.Set(k, v)
		}
		return true
	}

	return false
}

func (m HTTPRequestMatcher) String() string {
	return fmt.Sprintf("is http.Request with header matching %v", m.ExpectHeader)
}

// TimeStringMatcher matches strings containing timestamps
type TimeStringMatcher struct {
	gomock.Matcher
}

// Matches checks whether the string is a valid RFC3339 or Unix timestamp
func (m TimeStringMatcher) Matches(x interface{}) bool {
	timeStr, ok := x.(string)
	if ok {
		_, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			_, err := time.Parse(time.UnixDate, timeStr)
			return err == nil
		}
		return true
	}

	return false
}

func (m TimeStringMatcher) String() string {
	return "is a string with a timestamp"
}
