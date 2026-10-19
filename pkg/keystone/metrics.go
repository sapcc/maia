// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company
// SPDX-License-Identifier: Apache-2.0

package keystone

import "github.com/prometheus/client_golang/prometheus"

var keystoneCacheHits = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "maia_keystone_cache_hits_total",
	Help: "Number of keystone cache lookups that were served from cache, by cache type",
}, []string{"cache"})

var keystoneCacheMisses = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "maia_keystone_cache_misses_total",
	Help: "Number of keystone cache lookups that required a live Keystone call, by cache type",
}, []string{"cache"})

func init() {
	prometheus.MustRegister(keystoneCacheHits, keystoneCacheMisses)
}
