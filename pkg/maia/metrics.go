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

package maia

import (
	"log"

	"github.com/sapcc/maia/pkg/keystone"
	"github.com/sapcc/maia/pkg/storage"
	"github.com/sapcc/maia/pkg/util"
)

// Metric contains a data point
type Metric struct {
	Type  string
	Value string
}

// ListMetrics returns a list of matching metrics (with filtering)
func ListMetrics(tenantID string, keystoneDriver keystone.Driver, metricsStore storage.Driver) ([]*Metric, error) {

	util.LogDebug("maia.GetMetrics: tenant id is %s", tenantID)

	// TODO

	return nil, nil
}

func namesForIDs(keystoneDriver keystone.Driver, idMap map[string]string, targetType string) map[string]string {
	nameMap := map[string]string{}
	var err error

	// Now add the names for IDs in the metrics
	domainID := idMap["domain"]
	if domainID != "" {
		nameMap["domain"], err = keystoneDriver.DomainName(domainID)
		if err != nil {
			log.Printf("Error looking up domain name for domain '%s'", domainID)
		}
	}
	projectID := idMap["project"]
	if projectID != "" {
		nameMap["project"], err = keystoneDriver.ProjectName(projectID)
		if err != nil {
			log.Printf("Error looking up project name for project '%s'", projectID)
		}
	}
	userID := idMap["user"]
	if userID != "" {
		nameMap["user"], err = keystoneDriver.UserName(userID)
		if err != nil {
			log.Printf("Error looking up user name for user '%s'", userID)
		}
	}

	// Depending on the type of the target, we need to look up the name in different services
	switch targetType {
	case "data/security/project":
		nameMap["target"], err = keystoneDriver.ProjectName(idMap["target"])
	case "service/security/account/user":
		nameMap["target"], err = keystoneDriver.UserName(idMap["target"])
	default:
		log.Printf("Unhandled payload type \"%s\", cannot look up name.", targetType)
	}
	if err != nil {
		log.Printf("Error looking up name for %s '%s'", targetType, userID)
	}

	return nameMap
}
