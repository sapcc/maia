// SPDX-FileCopyrightText: 2017 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/spf13/viper"

	"github.com/sapcc/go-bits/httpext"
	"github.com/sapcc/go-bits/logg"

	"github.com/SAP-cloud-infrastructure/maia/pkg/keystone"
	"github.com/SAP-cloud-infrastructure/maia/pkg/storage"
	newui "github.com/SAP-cloud-infrastructure/maia/web/ui"
)

var storageInstance storage.Driver
var keystoneInstance keystone.Driver
var globalKeystoneInstance keystone.Driver

// sentinelValue is the configured global visibility sentinel, resolved once at
// startup. When non-empty, it is appended to project_id/domain_id scope
// constraints so that metrics carrying this value are visible to all tenants.
var sentinelValue string

// Server initializes and starts the API server, hooking it up to the API router
func Server(ctx context.Context) error {
	prometheusAPIURL := viper.GetString("maia.prometheus_url")
	if prometheusAPIURL == "" {
		panic(errors.New("prometheus endpoint not configured (maia.prometheus_url / MAIA_PROMETHEUS_URL)"))
	}

	// Initialize regular keystone driver
	keystoneDriver := keystone.NewKeystoneDriver()

	// Initialize global keystone if configured
	var globalKeystone keystone.Driver
	if viper.IsSet("keystone.global.auth_url") {
		logg.Info("Initializing global Keystone connection to %s", viper.GetString("keystone.global.auth_url"))
		globalKeystone = keystone.NewKeystoneDriverWithSection("global")
		globalKeystoneInstance = globalKeystone
	}

	// Validate and resolve sentinel value for global metric visibility (once at startup)
	sentinelValue = viper.GetString("maia.label_value_for_global_visibility")
	if sentinelValue != "" {
		if regexp.QuoteMeta(sentinelValue) != sentinelValue {
			panic(fmt.Errorf("maia.label_value_for_global_visibility contains regex metacharacters (value: %q); it must be a plain literal because it is injected into scope regexes verbatim", sentinelValue))
		}
		logg.Info("Global metric visibility sentinel configured: %q (appended to project_id/domain_id scope constraints)", sentinelValue)
	}

	// The main router dispatches all incoming requests
	mainRouter := setupRouter(keystoneDriver, globalKeystone, storage.NewPrometheusDriver(prometheusAPIURL, map[string]string{}))

	bindAddress := viper.GetString("maia.bind_address")
	logg.Info("listening on %s", bindAddress)

	// enable CORS
	c := cors.New(cors.Options{
		AllowedHeaders: []string{"X-Auth-Token", "X-Global-Region"},
	})
	handler := c.Handler(mainRouter)

	// start HTTP server and block; shuts down gracefully when ctx is cancelled
	return httpext.ListenAndServeContext(ctx, bindAddress, handler)
}

// setupRouter initializes the main http router
func setupRouter(keystoneDriver, globalKeystoneDriver keystone.Driver, storageDriver storage.Driver) http.Handler {
	storageInstance = storageDriver
	keystoneInstance = keystoneDriver
	globalKeystoneInstance = globalKeystoneDriver

	mainRouter := mux.NewRouter()

	// Add keystone resolution middleware early in the chain
	// This prevents race conditions by determining keystone instance once per request
	mainRouter.Use(keystoneResolutionMiddleware)

	// Root always redirects to the new React UI
	mainRouter.Methods(http.MethodGet).Path("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/query", http.StatusFound)
	})

	// Readiness probe used by the React UI's ReadinessWrapper
	mainRouter.Methods(http.MethodGet).Path("/-/ready").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("Maia is Ready.")); err != nil {
			logg.Error("failed to write ready response: %v", err)
		}
	})

	// the API is versioned, other paths are not
	apiRouter := mainRouter.PathPrefix("/api/").Subrouter()
	mainRouter.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		allVersions := struct {
			Versions []VersionData `json:"versions"`
		}{[]VersionData{versionData()}}
		ReturnJSON(w, http.StatusMultipleChoices, allVersions)
	})
	// hook up the v1 API (this code is structured so that a newer API version can
	// be added easily later)
	v1Handler := NewV1Handler(keystoneDriver, storageDriver)
	apiRouter.PathPrefix("/v1/").Handler(http.StripPrefix("/api/v1", v1Handler))

	// other endpoints
	// maia's federate endpoint
	mainRouter.Methods(http.MethodGet).Path("/federate").HandlerFunc(
		authorize(observeDuration(Federate, "federate"), false, "metric:show"))
	// /graph (no domain) — redirect to new UI
	mainRouter.Methods(http.MethodGet).Path("/graph").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/query", http.StatusFound)
	})
	// scrape endpoint for Prometheus
	mainRouter.Handle("/metrics", promhttp.Handler())

	// /{domain} — login entry point. Authenticates via any supported method
	// (X-Auth-Token cookie, Basic Auth, application credentials, x-auth-token
	// query param, or POST body field), sets the auth cookie, then redirects.
	// Supported entry points:
	//   GET  /{domain}?x-auth-token=<token>  — Elektra deep-link (existing)
	//   POST /{domain}  body: x-auth-token=<token>  — Elektra form POST (new)
	// Both /{domain} and /{domain}/graph route here for backwards compatibility.
	mainRouter.Methods(http.MethodGet).Path("/{domain}").HandlerFunc(
		authorize(loginAndRedirect, true, "metric:show"))
	mainRouter.Methods(http.MethodGet).Path("/{domain}/graph").HandlerFunc(
		authorize(loginAndRedirect, true, "metric:show"))

	// POST /{domain} — Elektra submits a form POST (application/x-www-form-urlencoded)
	// with x-auth-token in the body. The token is promoted to X-Auth-Token header
	// (priority: existing header > body field) before the standard auth+cookie flow runs.
	// On success, redirects to GET /{domain} (Post-Redirect-Get) so the browser
	// URL is clean and the token is no longer visible in the address bar.
	postDomainLogin := authorize(func(w http.ResponseWriter, req *http.Request) {
		domain := mux.Vars(req)["domain"]
		http.Redirect(w, req, "/"+domain, http.StatusFound)
	}, true, "metric:show")
	mainRouter.Methods(http.MethodPost).Path("/{domain}").HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if req.Header.Get("X-Auth-Token") == "" {
				if token := req.PostFormValue("x-auth-token"); token != "" {
					req.Header.Set("X-Auth-Token", token)
				}
			}
			postDomainLogin(w, req)
		})

	// New React UI routes
	mainRouter.Methods(http.MethodGet).Path("/ui").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/query", http.StatusFound)
	})
	// Strip /ui/ prefix; MantineUIAssets is rooted at mantine-ui/
	// so /ui/assets/foo.js → assets/foo.js inside MantineUIAssets
	uiFileServer := http.StripPrefix("/ui/", http.FileServer(newui.MantineUIAssets))
	mainRouter.Methods(http.MethodGet).PathPrefix("/ui/assets/").Handler(uiFileServer)
	mainRouter.Methods(http.MethodGet).Path("/ui/favicon.svg").Handler(uiFileServer)
	mainRouter.Methods(http.MethodGet).Path("/ui/manifest.json").Handler(uiFileServer)
	// SPA catch-all: all other /ui/* paths get index.html
	mainRouter.Methods(http.MethodGet).PathPrefix("/ui/").HandlerFunc(serveReactApp)

	// provide the inflight metrics for all paths
	return gaugeInflight(mainRouter)
}

// loginAndRedirect is the /{domain}/graph handler after the expression browser
// is removed. The authorize() wrapper authenticates the request via all
// supported mechanisms (X-Auth-Token cookie, Basic Auth, application
// credentials) and sets the auth cookie. This handler then redirects to the
// new React UI, completing the login flow.
func loginAndRedirect(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, "/ui/query", http.StatusFound)
}

// Federate handles GET /federate.
func Federate(w http.ResponseWriter, req *http.Request) {
	// Get keystone from context (secure, race-condition-free approach)
	ks := getKeystoneFromContext(req.Context())
	if ks == nil {
		// Context-based keystone resolution is mandatory for security
		logg.Error("Missing keystone context in Federate - request may have bypassed keystoneResolutionMiddleware")
		ReturnPromError(w, errors.New("keystone context not available"), http.StatusInternalServerError)
		return
	}

	selectors, err := buildSelectors(req, ks)
	if err != nil {
		logg.Info("Invalid request params %s", req.URL)
		ReturnPromError(w, err, http.StatusBadRequest)
		return
	}

	response, err := storageInstance.Federate(*selectors, req.Header.Get("Accept"))
	if err != nil {
		logg.Error("Could not get metrics for %s", selectors)
		ReturnPromError(w, err, http.StatusServiceUnavailable)
		return
	}

	ReturnResponse(w, response)
}

// serveReactApp serves the Maia React UI SPA for all /ui/* paths.
// It reads index.html from the embedded assets and replaces Prometheus
// placeholders with Maia-appropriate values before writing the response.
func serveReactApp(w http.ResponseWriter, req *http.Request) {
	f, err := newui.MantineUIAssets.Open("index.html")
	if err != nil {
		http.Error(w, "UI not available", http.StatusNotFound)
		return
	}
	defer f.Close()

	html, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "failed to read UI", http.StatusInternalServerError)
		return
	}

	html = bytes.ReplaceAll(html, []byte("TITLE_PLACEHOLDER"), []byte("Maia"))
	html = bytes.ReplaceAll(html, []byte("AGENT_MODE_PLACEHOLDER"), []byte("false"))
	html = bytes.ReplaceAll(html, []byte("READY_PLACEHOLDER"), []byte("true"))
	html = bytes.ReplaceAll(html, []byte("CONSOLES_LINK_PLACEHOLDER"), []byte(""))
	html = bytes.ReplaceAll(html, []byte("LOOKBACKDELTA_PLACEHOLDER"), []byte(""))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(html); err != nil {
		logg.Error("failed to write React UI response: %v", err)
	}
}
