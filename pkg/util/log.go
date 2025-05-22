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

package util

import (
	"os"

	"github.com/sapcc/go-bits/logg"
)

func init() {
	// Set debug mode based on environment variable
	if os.Getenv("MAIA_DEBUG") == "1" {
		logg.ShowDebug = true
	}
}

// LogFatal logs a fatal error and terminates the program.
func LogFatal(msg string, args ...interface{}) {
	logg.Fatal(msg, args...)
}

// LogError logs a non-fatal error.
func LogError(msg string, args ...interface{}) {
	logg.Error(msg, args...)
}

// LogWarning logs a warning of a potential error.
func LogWarning(msg string, args ...interface{}) {
	logg.Other("WARNING", msg, args...)
}

// LogInfo logs an informational message.
func LogInfo(msg string, args ...interface{}) {
	logg.Info(msg, args...)
}

// LogDebug logs a debug message if debug logging is enabled.
func LogDebug(msg string, args ...interface{}) {
	logg.Debug(msg, args...)
}
