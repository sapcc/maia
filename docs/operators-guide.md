# Maia Operators Guide

This guide describes how to set-up Maia as an OpenStack service and connect it to a Prometheus TSDB.

## Introduction

Maia is depending on an existing\* Prometheus installation that is responsible for collecting metrics. These metrics are exposed
by Maia using the same, familiar Prometheus API. The only difference is that all API requests have to be authenticated and scoped using
either OpenStack identity tokens or basic authentication.

\* If you do not have a running installation of Prometheus, you can download Prometheus from the
[Prometheus.io website](https://prometheus.io/download/) and get it up and running quickly with e.g. Docker.

Once Prometheus is up and running you need to attach Maia to your OpenStack identity service.

Last not least you have to come-up with some tenant-aware metrics. For that you will need exporters that you attach to
your Prometheus instance.

## Configuration

The service is configured using a TOML configuration file that is usually located in `etc/maia/maia.conf`. This file
contains settings for the connection to Prometheus, the integration with OpenStack identity and technical configuration
like the bind-address of the server process. You can always override the entries of this file using command line parameters.

Use the example in the `etc` folder of this repo to get started.

The *maia* section contains Maia-specific options.

```
[maia]
```

### Connectivity

First you need to decide which port the Maia service should listen to.
```
bind_address = "0.0.0.0:9091"
```

### Prometheus/Thanos

Any data served by Maia is served by the underlying Prometheus installation that acts as a TSDB and data collection layer.

To reach Prometheus, Maia needs to know the URL where it is running and optionally a proxy to get through.

```
prometheus_url = "http://myprometheus:9090"
# proxy = proxy for reaching <prometheus_url>
```

If you use _Thanos_, you have to provide the Thanos _querier_ address in the `prometheus_url`. Since the _querier_ does not
support the `federate` API [yet](https://github.com/thanos-io/thanos/pull/1546), you have specify another parameter `federate_url` which should point to an endpoint that supports it.
Usually this will be a Prometheus that has recent datapoints for _all_ the series the _querier_ knows (except for stale ones).

```
prometheus_url = "http://mythanos:9090/thanos"
federate_url = "http://myprometheus:9090"
# proxy = proxy for reaching <prometheus_url>
```

### Performance

The Prometheus API does not offer an efficient way to list known all historic label values for a given tenant. This
makes the [label-values API](https://prometheus.io/docs/querying/api/#querying-label-values) implementation a
complex operation.

In tenants with a high number of metric series, it is therefore highly recommended to limit the lifetime of label
values, so that older series with no recent data are not considered by the API. Otherwise you risk timeouts
and/or overload of your Prometheus backend. As a side-effect users of templated Grafana dashboards will not be
confronted with stale series in the dropdown boxes.

```
# ignore label values from series older than 2h
label_value_ttl = "2h"
```

### Keystone Integration

The *keystone* section contains configuration settings for OpenStack authentication and authorization.

```
[keystone]
```

#### OpenStack Service User

The maia service requires an OpenStack *service* user in order to authenticate and authorize clients.

```
# Identity service used to authenticate user credentials (create/verify tokens etc.)
auth_url = "https://identity.mydomain.com/v3/"
# service user credentials
username = "maia"
password = "asafepassword"
user_domain_name = "Default"
project_name = "serviceusers"
project_domain_name = "Default"
```

#### Authorization

An OpenStack [policy file](https://docs.openstack.org/security-guide/identity/policies.html) controls the
authorization of incoming requests. The roles mentioned in the policy file also need to be
listed in the configuration, so that Maia can discover which projects are relevant
for monitoring.

```
policy_file = "/etc/maia/policy.json"
roles = "monitoring_viewer,monitoring_admin"
```

You can also use regular expressions for role names, e.g. `.*` to check that a user has _some_ role.

Maia distinguishes the following permissions

* `metric:list`: List which metrics and measurement series are available for inspection
* `metric:show`: Show actual measurement data (details)

#### Default Domain

To logging into the UI without specifying a user-domain, you can specify which user-domain should be used
by default. By default this is the `Default` domain of OpenStack.

```
default_user_domain_name = "myOSDomain"
```

#### Token Cache

In order to improve responsiveness and protect Keystone from too much load, Maia will
re-check authorizations for users only every 15 minutes (900 seconds).

If the token TTL configured at Keystone is shorter or if you want to reduce Keystone load further,
this amount can be changed:

```
token_cache_time = "3600s"
```

## Global Keystone Configuration

Maia supports virtual region querying via a global keystone instance. This allows users to authenticate once and query metrics for a virtual global region.

### Configuration

To enable global keystone support, add the following to your configuration file:

```yaml
keystone:
  auth_url: https://identity-3.example.com/v3
  username: maia
  password: secret
  user_domain_name: Default
  project_name: service
  project_domain_name: Default
  
global_keystone:
  auth_url: https://global-identity.example.com/v3
  username: maia-global
  password: global-secret
  user_domain_name: Default
  project_name: service
  project_domain_name: Default
```

## Starting the Service

Once you have finalized the configuration file, you are set to go

```
maia serve
```

## Getting Data: Exporters

Maia is useless without metrics. So you need Prometheus exporters that provide tenant-aware metrics. These exporters
need to be scraped by the Prometheus instance that is configured as Maia's data source.

Multi-tenant support is provided by means of dedicated _labels_ to specify OpenStack project and domain.
These labels either have to be supplied by the exporters directly or they have to be mapped from other labels using the
[Prometheus relabelling](https://prometheus.io/docs/operating/configuration/#relabel_config)
capabilities.

The following labels have a special meaning in Maia. *Only metrics with these labels are visible through the Maia API.*

| Label Key  | Description  |
|:------------:|:--------------:|
| project_id | OpenStack project UUID |
| domain_id  | OpenStack domain UUID |

Metrics without `project_id` will be omitted when project scope is used. Likewise, metrics without `domain_id` will not
be available when authorized to domain scope.

Users authorized to a project will be able to access the metrics of all sub-projects. Users authorized to a domain will be able to access the metrics of all projects in that domain that have been labelled for the domain.

The following exporters are known to produce suitible metrics:

* [VCenter Exporter](https://github.com/sapcc/vcenter-exporter) provides project-specific metrics from an OpenStack-
controlled VCenter.
* [SNMP Exporter](https://github.com/prometheus/snmp_exporter) can be configured to extract project IDs from
SNMP variables into labels. Since most of the SNMP-enabled devices are shared, only a few metrics can be mapped to
OpenStack projects or domains.

## Monitoring

Maia offers a Prometheus scrape endpoint at the usual `/metrics` path.

This endpoint includes documentation and type-information for each metric. Refer to the Prometheus web site for more information on [naming conventions](https://prometheus.io/docs/practices/naming/) and [metric types](https://prometheus.io/docs/concepts/metric_types).

## Notes on Scalability

Currently Maia only supports a single Prometheus backend as data source. Therefore scalability has to happen behind the
Prometheus that is used by Maia.

Availability can be improved by setting up multiple identical Prometheus instances and using a reverse proxy for failover. Maia itself
is stateless, so multiple instances can be spawned without risking collisions.
