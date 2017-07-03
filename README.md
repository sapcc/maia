# Maia

[![Build Status](https://travis-ci.org/sapcc/maia.svg?branch=master)](https://travis-ci.org/sapcc/maia)
[![Coverage Status](https://coveralls.io/repos/github/sapcc/maia/badge.svg?branch=master)](https://coveralls.io/github/sapcc/maia?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/sapcc/maia)](https://goreportcard.com/report/github.com/sapcc/maia)
[![GoDoc](https://godoc.org/github.com/sapcc/maia?status.svg)](https://godoc.org/github.com/sapcc/maia)

Maia is an OpenStack-compatible service that allows querying Prometheus metrics per OpenStack project or domain.
It was originally designed for the SAP Converged Cloud.

# Design

![Architecture diagram](./docs/maia-architecture.png)

# LIMITATIONS

Before reading on and trying, please be aware that the following limitations exist
* protobuf-protocol is not tested and will probably fail for the label-values API
* keystone integration is not efficient: tokens are probably not cached
* the output format is raw, so the output is hard to use in scripts

# Installation

Via Makefile

* `make` to compile and run the binaries from the `build/` directory
* `make && make install` to install to `/usr`
* `make && make install PREFIX=/some/path` to install to `/some/path`
* `make docker` to build the Docker image (set image name and tag with the `DOCKER_IMAGE` and `DOCKER_TAG` variables)


# Using Maia as Service

Maia is depending on an existing\* Prometheus installation that is responsible for collecting metrics. These metrics are exposed
by Maia using the same, familiar Prometheus API. The only difference is that all API requests have to be authenticated and scoped using
either OpenStack identity tokens or basic authentication.

\* If you do not have a running installation of Prometheus, you can download Prometheus from the
[Prometheus.io website](https://prometheus.io/download/) and get it up and running quickly with e.g. Docker.

## Configuration

The service is configured using a TOML configuration file that is usually located in `etc/maia/maia.conf`. This file
contains settings for the connection to Prometheus, the integration with OpenStack identity and technical configuration
like the bind-address of the server process.

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

To reach Prometheus, Maia needs to know the URL where it is running and optionally a proxy to get through.

```
prometheus_url = "http://myprometheus:9090"
# proxy = proxy for reaching <prometheus_url>
```

### Authorization Roles

An OpenStack [policy file](https://docs.openstack.org/security-guide/identity/policies.html) controls the
authorization of incoming requests.  

```
policy_file = "/etc/maia/policy.json"
```

### Performance

The Prometheus API does not offer an efficient way to list known all historic label values for a given tenant. This
makes the [label-values API](https://prometheus.io/docs/querying/api/#querying-label-values) implementation a
complex operation.

In tenants with a high number of metric series, it is therefore highly recommended to limit the lifetime of label
values, so that older series with no recent data are not considered. Otherwise you risk timeouts and/or overloading
of your Prometheus backend.

```
# ignore label values from series with no new metrics since more than 2h 
label_value_ttl = "2h"
```

### OpenStack Service User

The maia service requires an OpenStack *service* user in order to authenticate and authorize clients.
 
```
[keystone]
# Identity service used to authenticate user credentials (create/verify tokens etc.)
auth_url = "https://identity.mydomain.com/v3/"
# service user credentials
username = "maia"
password = "asafepassword"
user_domain_name = "Default"
project_name = "serviceusers"
project_domain_name = "Default"
```

## Starting the Service

Once you have finalized the configuration file, you are set to go

```
maia serve
```

# Using the Maia Client

The `maia` command can also be used to retrieve metrics from the Maia service. It behaves like any other OpenStack
 CLI, supporting the same command line options and environment variables. You can reuse your existing RC-files
 for authentication.
 
In the examples below we assume that you have initialized the OS_* variables your shell environment properly and that
your user has the prerequisite roles (e.g. `monitoring_viewer`) on the project in scope.

Type `maia --help` to get a full list of commands and options options.

```
maia --help
```

## Fetch Current Metrics

Use the `metrics` command to get current metric values in textual form. 

```
maia metrics --maia-url http://localhost:9091
```

The amount of data can be restricted using Prometheus selectors, i.e. constraints on label values:

```
maia metrics --maia-url http://localhost:9091
```

## Common Options

### Output Format

tbd: json, tabular output, csv, single values

### Use Maia Client with Prometheus

You can also use the maia client with a plain Prometheus (no authentication)

```
maia metrics --prometheus-url http://localhost:9090
```

# Federating Tenant Metrics from Maia to another Prometheus

To configure Prometheus to receive data from Maia, the following job configuration has to be applied.
In the `basic_auth` section a valid user id, project id and password, corresponding to your OpenStack User and Project, has to be provided.
Moreover the user is required to have the `metric-list` role.

```yaml
scrape_configs:

  # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
  - job_name: 'maia'
    metrics_path: "/federate"
    basic_auth:
      # Corresponds to your OpenStack User and Project
      username: <user_id>|<project_id>
      password: <password>

    static_configs:
      - targets: ['maia.<region>.cloud.sap:443']
  
```

Prometheus' targets page ( Status -> Targets ) should the new job and the endpoint with `State UP`. 
The `Error` column should be empty. 
It might indicate a failed authorization (`401 Unauthorized`).
