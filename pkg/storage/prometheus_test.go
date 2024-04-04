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

func setupTest(t *testing.T) Driver { //nolint:unparam
	// load test policy (where everything is allowed)
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
func assertDone(t *testing.T) bool { //nolint:unparam
	return assert.True(t, gock.IsDone(), "pending mocks: %v\nunmatched requests: %v", mocksToStrings(gock.Pending()), gock.GetUnmatchedRequests())
}

func TestFederate(t *testing.T) {
	defer gock.Off()

	ps := setupTest(t)

	gock.New(federateURL).Get("/federate").
		MatchParams(map[string]string{"match[]": "{vmware_name=\"win_cifs_13\",project_id=\"p00001\"}"}).
		Reply(http.StatusOK).
		File("fixtures/federate.txt").
		AddHeader("Content-Type", PlainText)

	_, err := ps.Federate([]string{"{vmware_name=\"win_cifs_13\",project_id=\"p00001\"}"}, PlainText)

	assert.Nil(t, err, "Federate should not fail")

	assertDone(t)
}

func TestLabelValues(t *testing.T) {
	defer gock.Off()

	ps := setupTest(t)

	gock.New(prometheusURL).Get("/api/v1/label/service/values").
		Reply(http.StatusOK).
		File("fixtures/label_values.json").
		AddHeader("Content-Type", JSON)

	_, err := ps.LabelValues("service", JSON)

	assert.Nil(t, err, "label/.../values should not fail")

	assertDone(t)
}

// TestLabels I tried to match this similarly to TestLabelValues
// It passes, but I can't seem to sort out if it actually works.
// It feels like it's not actually using the fixture, but I'm not sure.
func TestLabels(t *testing.T) {
	defer gock.Off()

	ps := setupTest(t)

	// Mock the labels endpoint
	gock.New(prometheusURL).Get("/api/v1/labels").
		Reply(http.StatusOK).
		File("fixtures/label_names.json").
		AddHeader("Content-Type", JSON)

	start := "2023-05-12T00:00:00Z"
	end := "2023-05-12T23:59:59Z"
	match := []string{"project_id=\"p00001\""}
	_, err := ps.Labels(start, end, match, JSON)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, err, "labels should not fail")

	assertDone(t)
}
