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

package api

import (
	"bytes"
	"encoding/json"
	"github.com/sapcc/maia/pkg/storage"
	"io"
	"net/http"
	"strings"
)

// utility functionality

//ReturnResponse basically forwards a received Response.
func ReturnResponse(w http.ResponseWriter, response *http.Response) {
	defer response.Body.Close()

	// copy headers
	for k, v := range response.Header {
		w.Header().Set(k, strings.Join(v, ";"))
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	body := buf.String()
	w.WriteHeader(response.StatusCode)

	io.WriteString(w, body)
}

//ReturnJSON is a convenience function for HTTP handlers returning JSON data.
//The `code` argument specifies the HTTP Response code, usually 200.
func ReturnJSON(w http.ResponseWriter, code int, data interface{}) {
	escapedJSON, err := json.Marshal(&data)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		// TODO: @Arno, what is this good for?
		jsonData := bytes.Replace(escapedJSON, []byte("\\u0026"), []byte("&"), -1)
		w.Write(jsonData)
	} else {
		http.Error(w, err.Error(), 500)
	}
}

//ReturnError produces a Prometheus error Response with HTTP Status code if the given
//error is non-nil. Otherwise, nothing is done and false is returned.
func ReturnError(w http.ResponseWriter, err error, code int) bool {
	if err == nil {
		return false
	}

	var errorType = storage.ErrorNone
	switch code {
	case 400:
		errorType = storage.ErrorBadData
	case 422:
		errorType = storage.ErrorExec
	case 500:
		errorType = storage.ErrorInternal
	case 503:
		errorType = storage.ErrorTimeout
	default:
		http.Error(w, err.Error(), code)
		return true
	}

	jsonErr := storage.Response{Status: storage.StatusError, ErrorType: errorType, Error: err.Error()}
	ReturnJSON(w, code, jsonErr)

	return true
}
