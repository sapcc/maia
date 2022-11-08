/*******************************************************************************
*
* Copyright 2017 Stefan Majewsky <majewsky@gmx.net>
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

package test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/sapcc/maia/pkg/storage"
)

// APIRequest contains all metadata about a test request.
type APIRequest struct {
	Headers          map[string]string
	Method           string
	Path             string
	RequestJSON      interface{} //if non-nil, will be encoded as JSON
	ExpectStatusCode int
	ExpectBody       *string //raw content (not a file path)
	ExpectJSON       string  //path to JSON file
	ExpectFile       string  //path to arbitrary file
}

// Check performs the HTTP request described by this APIRequest against the
// given http.Handler and compares the response with the expectation in the
// APIRequest.
func (r APIRequest) Check(t *testing.T, handler http.Handler) {
	var requestBody io.Reader
	if r.RequestJSON != nil {
		body, err := json.Marshal(r.RequestJSON)
		if err != nil {
			t.Fatal(err)
		}
		requestBody = bytes.NewReader([]byte(body))
	}
	request := httptest.NewRequest(r.Method, r.Path, requestBody)
	for k, v := range r.Headers {
		request.Header.Set(k, v)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	response := recorder.Result()
	responseBytes, _ := io.ReadAll(response.Body)

	if response.StatusCode != r.ExpectStatusCode {
		t.Errorf("%s %s: expected status code %d, got %d",
			r.Method, r.Path, r.ExpectStatusCode, response.StatusCode,
		)
		debug.PrintStack()
	}

	switch {
	case r.ExpectBody != nil:
		responseStr := string(responseBytes)
		if responseStr != *r.ExpectBody {
			t.Fatalf("%s %s: expected body %#v, but got %#v",
				r.Method, r.Path, *r.ExpectBody, responseStr,
			)
		}
	case r.ExpectJSON != "":
		var buf bytes.Buffer
		err := json.Indent(&buf, responseBytes, "", "  ")
		if err != nil {
			t.Logf("Response body: %s", responseBytes)
			t.Fatal(err)
		}
		r.compareBodyToFixture(t, r.ExpectJSON, buf.Bytes())
	case r.ExpectFile != "":
		r.compareBodyToFixture(t, r.ExpectFile, responseBytes)
	}
}

func (r APIRequest) compareBodyToFixture(t *testing.T, fixturePath string, data []byte) {
	//write actual content to file to make it easy to copy the computed result over
	//to the fixture path when a new test is added or an existing one is modified
	fixturePathAbs, _ := filepath.Abs(fixturePath)
	actualPathAbs := fixturePathAbs + ".actual"
	err := os.WriteFile(actualPathAbs, data, 0644)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("diff", "-u", fixturePathAbs, actualPathAbs)
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		t.Fatalf("%s %s: body does not match: %s", r.Method, r.Path, err.Error())
	}
}

// HTTPResponseFromFile creates a response object from the contents of a file.
// It uses to suffix of the filename to determine the content-type
func HTTPResponseFromFile(filename string) *http.Response {
	fixture, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	responseRec := httptest.NewRecorder()
	var contentType string
	if strings.HasSuffix(filename, ".json") {
		contentType = storage.JSON
	} else if strings.HasSuffix(filename, ".txt") {
		contentType = storage.PlainText
	}
	responseRec.Header().Set("Content-Type", contentType)
	responseRec.Write(fixture)
	return responseRec.Result()
}
