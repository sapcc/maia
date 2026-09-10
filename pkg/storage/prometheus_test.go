// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"errors"
	"net/http"
	"net/url"
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

func TestPrometheusInitFederateURL(t *testing.T) {
	tests := []struct {
		name        string
		federateURL string
		wantURL     string
	}{
		{
			name:        "configured federate URL",
			federateURL: federateURL,
			wantURL:     federateURL,
		},
		{
			name:    "fallback to Prometheus URL",
			wantURL: prometheusURL,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			viper.Set("maia.proxy", "http://proxy.example.com:8080")
			if test.federateURL != "" {
				viper.Set("maia.federate_url", test.federateURL)
			}

			driver := Prometheus(prometheusURL, nil).(*prometheusStorageClient)
			if _, ok := driver.httpClient.Transport.(*http.Transport); !ok {
				t.Fatalf("transport type = %T, want *http.Transport", driver.httpClient.Transport)
			}
			if got := driver.federateURL.String(); got != test.wantURL {
				t.Errorf("federate URL = %q, want %q", got, test.wantURL)
			}
		})
	}
}

func TestPrometheusInitProxy(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("maia.proxy", "http://proxy.example.com:8080")

	driver := Prometheus(prometheusURL, nil).(*prometheusStorageClient)
	transport, ok := driver.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", driver.httpClient.Transport)
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport type = %T, want *http.Transport", http.DefaultTransport)
	}
	if transport == defaultTransport {
		t.Fatal("transport must clone http.DefaultTransport before setting the proxy")
	}
	if got, want := transport.IdleConnTimeout, defaultTransport.IdleConnTimeout; got != want {
		t.Errorf("IdleConnTimeout = %v, want default transport value %v", got, want)
	}

	req, err := http.NewRequest(http.MethodGet, prometheusURL, http.NoBody)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	gotProxyURL, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("get proxy URL: %v", err)
	}
	if got, want := gotProxyURL.String(), "http://proxy.example.com:8080"; got != want {
		t.Errorf("proxy URL = %q, want %q", got, want)
	}
}

func TestPrometheusInitInvalidProxy(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("maia.proxy", "http://%zz")

	var recovered any
	func() {
		defer func() {
			recovered = recover()
		}()
		Prometheus(prometheusURL, nil)
	}()

	err, ok := recovered.(error)
	if !ok {
		t.Fatalf("panic value type = %T, want error", recovered)
	}
	if errors.Unwrap(err) == nil {
		t.Errorf("proxy parse error = %v, want a wrapped parse error", err)
	}
	assert.Contains(t, err.Error(), "parse proxy URL \"http://%zz\"")
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

// TestValidateUpstreamURL exercises the SSRF defense-in-depth check that backs
// CodeQL go/request-forgery. mapURL() rewrites Host/Scheme/User to the trusted
// upstream, so the validator should accept the configured Prometheus host and
// the federate host but reject anything else.
func TestValidateUpstreamURL(t *testing.T) {
	setupTest(t)
	driver := NewPrometheusDriver(prometheusURL, map[string]string{}).(*prometheusStorageClient)

	cases := []struct {
		name    string
		url     string
		wantErr string // substring match; empty = expect success
	}{
		{"trusted upstream", "http://thanos.local/thanos/api/v1/query", ""},
		{"trusted federate", "http://prometheus.local/federate", ""},
		{"foreign host rejected", "http://evil.example.com/api/v1/query", "untrusted host"},
		{"localhost rejected", "http://127.0.0.1:9090/api/v1/query", "untrusted host"},
		{"empty host rejected", "http:///api/v1/query", "empty host"},
		{"unknown scheme rejected", "file:///etc/passwd", "scheme"},
		{"ftp scheme rejected", "ftp://thanos.local/", "scheme"},
		{"malformed url rejected", "http://%zz", "invalid URL"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := driver.validateUpstreamURL(tc.url)
			if tc.wantErr == "" {
				assert.NoError(t, err, "expected %q to be accepted", tc.url)
				return
			}
			assert.Error(t, err, "expected %q to be rejected", tc.url)
			if err != nil {
				assert.Contains(t, err.Error(), tc.wantErr, "wrong rejection reason for %q", tc.url)
			}
		})
	}
}

// TestSendToPrometheusRejectsUntrustedHost ensures the validation actually
// blocks an outbound request, not just returns an error from a helper.
func TestSendToPrometheusRejectsUntrustedHost(t *testing.T) {
	defer gock.Off()
	setupTest(t)
	driver := NewPrometheusDriver(prometheusURL, map[string]string{}).(*prometheusStorageClient)

	// No gock mock registered — if validation fails to block, the request would
	// hit the real network (or gock's "unmatched" path) and we'd see a different
	// error. Validation must short-circuit before any HTTP call.
	resp, err := driver.sendToPrometheus("GET", "http://attacker.invalid/api/v1/query", nil, nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "untrusted host")
}

// TestBuildURLNoDoubleSlash verifies that a trailing slash on the configured
// prometheus_url does not produce a double-slash path segment.
// A double slash caused HTTP 301 redirects which stripped the POST body.
func TestBuildURLNoDoubleSlash(t *testing.T) {
	cases := []struct {
		base string
		path string
		want string
	}{
		{"http://thanos.local/thanos/", "/api/v1/query_range", "http://thanos.local/thanos/api/v1/query_range"},
		{"http://thanos.local/thanos", "/api/v1/query_range", "http://thanos.local/thanos/api/v1/query_range"},
		{"http://thanos.local/", "/api/v1/query", "http://thanos.local/api/v1/query"},
		{"http://thanos.local", "/api/v1/query", "http://thanos.local/api/v1/query"},
	}
	for _, tc := range cases {
		t.Run(tc.base, func(t *testing.T) {
			u, err := url.Parse(tc.base)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tc.base, err)
			}
			client := &prometheusStorageClient{url: u, federateURL: u, httpClient: &http.Client{}}
			got := client.buildURL(tc.path, map[string]any{})
			assert.Equal(t, tc.want, got.String())
			assert.NotContains(t, got.Path, "//", "path must not contain double slashes")
		})
	}
}

// TestQueryUsesPost verifies that Query sends a POST request with the query
// in the form body rather than in the URL, bypassing proxy URL length limits.
func TestQueryUsesPost(t *testing.T) {
	defer gock.Off()
	ps := setupTest(t)

	gock.New(prometheusURL).
		Post("/api/v1/query").
		MatchHeader("Content-Type", "application/x-www-form-urlencoded").
		Reply(http.StatusOK).
		BodyString("{}").
		AddHeader("Content-Type", JSON)

	_, err := ps.Query("up", "", "", JSON)
	assert.Nil(t, err)
	assertDone(t)
}

// TestQueryRangeUsesPost verifies that QueryRange sends a POST request with
// parameters in the form body, bypassing proxy URL length limits.
func TestQueryRangeUsesPost(t *testing.T) {
	defer gock.Off()
	ps := setupTest(t)

	gock.New(prometheusURL).
		Post("/api/v1/query_range").
		MatchHeader("Content-Type", "application/x-www-form-urlencoded").
		Reply(http.StatusOK).
		BodyString("{}").
		AddHeader("Content-Type", JSON)

	_, err := ps.QueryRange("up", "2024-01-01T00:00:00Z", "2024-01-01T01:00:00Z", "1h", "", JSON)
	assert.Nil(t, err)
	assertDone(t)
}
