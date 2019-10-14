package storage

import (
	"net/http"
	"testing"

	"github.com/h2non/gock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const (
	prometheusURL = "http://thanos.local/thanos"
	federateURL   = "http://prometheus.local"
)

func setupTest(t *testing.T) Driver {
	//load test policy (where everything is allowed)
	viper.Set("maia.storage_driver", "prometheus")
	viper.Set("maia.label_value_ttl", "72h")
	viper.Set("maia.prometheus_url", prometheusURL)
	viper.Set("maia.federate_url", federateURL)

	return NewPrometheusDriver(prometheusURL, map[string]string{})
}

func mocksToStrings(mocks []gock.Mock) []string {
	s := make([]string, len(mocks))
	for i, m := range mocks {
		r := m.Request()
		s[i] = r.Method + " " + r.URLStruct.String()
	}
	return s
}

func TestNewPrometheusDriver(t *testing.T) {
	defer gock.Off()

	setupTest(t)

	assertDone(t)
}
func assertDone(t *testing.T) bool {
	return assert.True(t, gock.IsDone(), "pending mocks: %v\nunmatched requests: %v", mocksToStrings(gock.Pending()), gock.GetUnmatchedRequests())
}

func TestFederate(t *testing.T) {
	defer gock.Off()

	ps := setupTest(t)

	gock.New(federateURL).Get("/federate").MatchParams(map[string]string{"match[]": "{vmware_name=\"win_cifs_13\",project_id=\"p00001\"}"}).Reply(http.StatusOK).File("fixtures/federate.txt").AddHeader("Content-Type", PlainText)

	_, err := ps.Federate([]string{"{vmware_name=\"win_cifs_13\",project_id=\"p00001\"}"}, PlainText)

	assert.Nil(t, err, "Federate should not fail")

	assertDone(t)
}
