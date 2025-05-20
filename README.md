<!--
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company

SPDX-License-Identifier: Apache-2.0
-->

# Maia

[![CI](https://github.com/sapcc/maia/actions/workflows/ci.yaml/badge.svg)](https://github.com/sapcc/maia/actions/workflows/ci.yaml)

Maia is a multi-tenant OpenStack-service for accessing metrics and alarms collected through Prometheus. It offers 
a [Prometheus-compatible](https://prometheus.io/docs/querying/api/) API and supports federation.

At SAP we use it to share tenant-specific metrics from our Converged Cloud platform
with our users. For their convenience we included a CLI, so that metrics can be discovered and
retrieved from shell scripts.

If you don't use OpenStack, you can still use Maia CLI as a feature-complete shell client for Prometheus. 

## Features

[Maia Service](docs/operators-guide.md)

* OpenStack Identity v3 authentication and authorization
* Project- and domain-level access control (scoping)
* Compatible to Grafana's Prometheus data source 
* Compatible to Prometheus API (read-only)
* Supports secure federation to additional Prometheus instances

[Maia UI](docs/users-guide.md#using-the-maia-ui)

* Prometheus expression browser adapted to Maia
* Browse projects and metrics
* Perform ad-hoc PromQL queries
* Graph metrics

[Maia CLI](docs/users-guide.md#using-the-maia-client)

* Feature-complete CLI supporting all API operations
* JSON and Go-template-based output for reliable automation
* Works with Prometheus, too (no OpenStack required)

## Installation

Maia can be built with Go 1.20. Older versions are not supported. Newer versions are not tested.

### Binary Releases

Binary releases for Linux and MacOS can be downloaded from the GitHub _releases_ area.

### Installation with make

* `make` to compile and run the binaries from the `build/` directory
* `make && make install` to install to `/usr`
* `make && make install PREFIX=/some/path` to install to `/some/path`
* `make docker` to build the Docker image (set image name and tag with the `DOCKER_IMAGE` and `DOCKER_TAG` variables)

## Using Maia

Maia can be used via Web-UI or CLI.

Enter `maia --help` to see a list of commands and options.

Please refer to the [Maia user guide](./docs/users-guide.md) for more instructions.

## Operating Maia

The easiest way to deploy Maia as a service is Kubernetes.

Feel free to reuse our [Maia helm chart](https://github.com/sapcc/helm-charts/tree/master/openstack/maia)
which includes Maia, Prometheus and Thanos.

Follow the [Maia operators guide](./docs/operators-guide.md) to learn how to setup the 
Maia service from scratch and integrate with Prometheus.

## Integrating and Extending Maia

The [Maia developers guide](./docs/developers-guide.md) describes how to use the Maia API. Also
it contains information how to contribute to the Maia development.

## Support, Feedback, Contributing

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/creating-an-issue). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](https://github.com/SAP-cloud-infrastructure/.github/blob/main/CONTRIBUTING.md).

## Security / Disclosure

If you find any bug that may be a security problem, please follow our instructions [in our security policy](https://github.com/SAP-cloud-infrastructure/.github/blob/main/SECURITY.md) on how to report it. Please do not create GitHub issues for security-related doubts or problems.

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](https://github.com/SAP-cloud-infrastructure/.github/blob/main/CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2017-2025 SAP SE or an SAP affiliate company and maia contributors. Please see our [LICENSE](LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available [via the REUSE tool](https://api.reuse.software/info/github.com/sapcc/maia).