// SPDX-FileCopyrightText: 2017 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/spf13/viper"

	"github.com/sapcc/go-bits/logg"
)

type prometheusStorageClient struct {
	httpClient       *http.Client
	url, federateURL *url.URL
	customHeaders    map[string]string
}

// Prometheus creates a storage driver for Prometheus/Maia
func Prometheus(prometheusAPIURL string, customHeaders map[string]string) Driver {
	parsedURL, err := url.Parse(prometheusAPIURL)
	if err != nil {
		panic(err)
	}
	result := prometheusStorageClient{
		url:           parsedURL,
		customHeaders: customHeaders,
	}
	result.init()
	return &result
}

func (promCli *prometheusStorageClient) init() {
	// if federateURL is configured, this will direct /federate requests to another host URL
	if viper.IsSet("maia.federate_url") {
		parsedURL, err := url.Parse(viper.GetString("maia.federate_url"))
		if err != nil {
			panic(err)
		}
		promCli.federateURL = parsedURL
	} else {
		promCli.federateURL = promCli.url
	}

	if viper.IsSet("maia.proxy") {
		proxyURLString := viper.GetString("maia.proxy")
		proxyURL, err := url.Parse(proxyURLString)
		if err != nil {
			panic(fmt.Errorf("parse proxy URL %q: %w", proxyURLString, err))
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = http.ProxyURL(proxyURL)
		promCli.httpClient = &http.Client{Transport: transport}
		return
	}
	promCli.httpClient = &http.Client{}
}

func (promCli *prometheusStorageClient) Query(query, time, timeout, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/api/v1/query", map[string]any{})
	form := url.Values{}
	if query != "" {
		form.Set("query", query)
	}
	if time != "" {
		form.Set("time", time)
	}
	if timeout != "" {
		form.Set("timeout", timeout)
	}
	return promCli.sendToPrometheus("POST", promURL.String(), strings.NewReader(form.Encode()),
		map[string]string{"Accept": acceptContentType, "Content-Type": "application/x-www-form-urlencoded"})
}

func (promCli *prometheusStorageClient) QueryRange(query, start, end, step, timeout, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/api/v1/query_range", map[string]any{})
	form := url.Values{}
	if query != "" {
		form.Set("query", query)
	}
	if start != "" {
		form.Set("start", start)
	}
	if end != "" {
		form.Set("end", end)
	}
	if step != "" {
		form.Set("step", step)
	}
	if timeout != "" {
		form.Set("timeout", timeout)
	}
	return promCli.sendToPrometheus("POST", promURL.String(), strings.NewReader(form.Encode()),
		map[string]string{"Accept": acceptContentType, "Content-Type": "application/x-www-form-urlencoded"})
}

func (promCli *prometheusStorageClient) Series(match []string, start, end, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/api/v1/series", map[string]any{"match[]": match, "start": start, "end": end})

	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

func (promCli *prometheusStorageClient) LabelValues(name, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/api/v1/label/"+name+"/values", map[string]any{})

	res, err := promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})

	return res, err
}

// LabelNames returns all label names that are used in the time series data ingested by the Prometheus instance.
// https://prometheus.io/docs/prometheus/latest/querying/api/#getting-label-names
// match[]=<series_selector>: Repeated series selector argument that selects the series to return. At least one match[] argument must be provided.
// Does this mean we need to use /api/v1/series to get the series selector?
func (promCli *prometheusStorageClient) Labels(start, end string, match []string, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/api/v1/labels", map[string]any{"start": start, "end": end, "match[]": match})

	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

func (promCli *prometheusStorageClient) Metadata(metric, limit, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/api/v1/metadata", map[string]any{"metric": metric, "limit": limit})
	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

func (promCli *prometheusStorageClient) Federate(selectors []string, acceptContentType string) (*http.Response, error) {
	promURL := promCli.buildURL("/federate", map[string]any{"match[]": selectors})

	return promCli.sendToPrometheus("GET", promURL.String(), nil, map[string]string{"Accept": acceptContentType})
}

// buildURL is used to build the target URL of a Prometheus call
func (promCli *prometheusStorageClient) buildURL(path string, params map[string]any) url.URL {
	promURL := *promCli.url
	// treat federate special
	if path == "/federate" {
		promURL = *promCli.federateURL
	}

	// change original request to point to our backing Prometheus
	promURL.Path = strings.TrimRight(promURL.Path, "/") + path
	queryParams := url.Values{}
	for k, v := range params {
		if s, ok := v.(string); ok {
			if s != "" {
				queryParams.Add(k, s)
			}
		} else {
			for _, s := range v.([]string) {
				queryParams.Add(k, s)
			}
		}
	}
	promURL.RawQuery = queryParams.Encode()

	return promURL
}

// sendToPrometheus takes care of the request wrapping and delivery to Prometheus.
func (promCli *prometheusStorageClient) sendToPrometheus(method, promURL string, body io.Reader, headers map[string]string) (*http.Response, error) {
	// Defense-in-depth: verify the URL targets a trusted upstream before sending.
	// All Driver methods construct URLs via buildURL() which uses only the
	// configured promCli.url / promCli.federateURL base, but this check makes
	// the safety property explicit and guards against future regressions.
	if err := promCli.validateUpstreamURL(promURL); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(context.Background(), method, promURL, body)
	if err != nil {
		logg.Error("Could not create request.\n", err.Error())
		return nil, err
	}

	for k, v := range promCli.customHeaders {
		req.Header.Add(k, v)
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	logg.Debug("Forwarding request to API: %s", promURL)

	resp, err := promCli.httpClient.Do(req)
	if err != nil {
		logg.Error("Request failed.\n%s", err.Error())
		return nil, err
	}
	return resp, nil
}

// validateUpstreamURL checks that the request URL is well-formed AND points at a
// trusted upstream host (the configured Prometheus URL or, for federation, the
// configured federate URL). This makes the SSRF safety property explicit so it is
// provable to a static analyzer and to future maintainers.
func (promCli *prometheusStorageClient) validateUpstreamURL(urlStr string) error {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", urlStr, err)
	}

	// Check if the scheme is http or https.
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid URL %q: scheme %q is not http or https", urlStr, parsedURL.Scheme)
	}

	// Check if the host is non-empty.
	if parsedURL.Host == "" {
		return fmt.Errorf("invalid URL %q: empty host", urlStr)
	}

	// Enforce that the host matches a trusted upstream. promCli.url is always set;
	// promCli.federateURL is set in init() (it falls back to promCli.url when no
	// dedicated federate URL is configured).
	allowedHosts := []string{promCli.url.Host}
	if promCli.federateURL != nil && promCli.federateURL.Host != promCli.url.Host {
		allowedHosts = append(allowedHosts, promCli.federateURL.Host)
	}
	if slices.Contains(allowedHosts, parsedURL.Host) {
		return nil
	}
	return fmt.Errorf("refusing request to untrusted host %q (expected one of %v)", parsedURL.Host, allowedHosts)
}
