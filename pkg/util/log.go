// SPDX-FileCopyrightText: 2017 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"log"
	"os"
	"strings"
)

var isDebug = os.Getenv("MAIA_DEBUG") == "1"

// LogFatal logs a fatal error and terminates the program.
func LogFatal(msg string, args ...interface{}) {
	doLog("FATAL: "+msg, args)
}

// LogError logs a non-fatal error.
func LogError(msg string, args ...interface{}) {
	doLog("ERROR: "+msg, args)
}

// LogWarning logs a warning of a potential error.
func LogWarning(msg string, args ...interface{}) {
	doLog("WARNING: "+msg, args)
}

// LogInfo logs an informational message.
func LogInfo(msg string, args ...interface{}) {
	doLog("INFO: "+msg, args)
}

// LogDebug logs a debug message if debug logging is enabled.
func LogDebug(msg string, args ...interface{}) {
	if isDebug {
		doLog("DEBUG: "+msg, args)
	}
}

func doLog(msg string, args []interface{}) {
	msg = strings.TrimSpace(msg)               // most importantly, skip trailing '\n'
	msg = strings.ReplaceAll(msg, "\n", "\\n") // avoid multiline log messages
	for i, arg := range args {
		if str, ok := arg.(string); ok {
			args[i] = strings.ReplaceAll(strings.ReplaceAll(str, "\n", ""), "\r", "")
		}
	}
	if len(args) > 0 {
		log.Printf(msg+"\n", args...)
	} else {
		log.Println(msg)
	}
}
