# Maia Developer Guide

Maia is a multi-tenant OpenStack-service for accessing metrics and alarms collected through Prometheus. It offers 
a [Prometheus-compatible](https://prometheus.io/docs/querying/api/) API and supports federation.

This guide describes how to integrate with the Maia service from applications using the Maia API.

Contributors will get an overview on Maia's design priciples and requirements to contributors. 

## Concept

Maia adds multi-tenant support to an existing Prometheus installation by using dedicated labels to assign metrics to
OpenStack projects and domains. These labels either have to be supplied by the exporters or they have to be
mapped from other labels using the [Prometheus relabelling](https://prometheus.io/docs/operating/configuration/#relabel_config)
capabilities.
 
The following labels have a special meaning in Maia. *Only metrics with these labels are visible through the Maia API.*
 
 | Label Key  | Description  |
 |------------|--------------|
 | project_id | OpenStack project UUID |
 | domain_id  | OpenStack domain UUID |
 
Metrics without `project_id` will be omitted when project scope is used. Likewise, metrics without `domain_id` will not
be available when authorized to domain scope.

Users authorized to a project will be able to access the metrics of all sub-projects. Users authorized to a domain will be able to access the metrics of all projects in that domain that have been labelled for the domain.

## Using the Maia API

The Maia implements the consumer part of the [Prometheus API](https://prometheus.io/docs/querying/api) and adds
OpenStack authentication and authorization on top. For security reasons, administrative operations of the API have not
been added to Maia. 

### OpenStack Authentication and Authorization

In addition to 'native' OpenStack authentication using Keystone tokens, Maia supports basic authentication in order 
to support existing clients like Grafana and federated Prometheus. 

The problem with basic authentication is that it lacks a standard way to express OpenStack domain information. Also there
 is no means to express OpenStack authorization scopes. Since neither Prometheus nor Grafana support adding custom
 header fields to the requests to Prometheus and thus Maia, we have to encode both the domain information and the authorization
 scope into the username.
 
 For the domain qualification, we could borrow "@" from e-mail. So when a user or a project is identified by name, you
  can add the domain in the form `username@domainname`. 
  
 The authorization scope is separated from the qualified username with a vertical bar "|", splitting the username
 into a username and scope part: `user|scope`. Like with usernames, also the scoped project resp. domain can be
 denoted by name: `projectname@domainname`. To disambiguate scoping by project-id and domain-name, the domain is always prefixed
 with `@`.
 
#### Variants
 
This scheme expands into five variants to express username and authorization scope:
 
Project scoped user:
* `user_id|project_id`
* `username@user_domain_name|project_id`
* `user_id|project_name@project_domain_name`
* `username@user_domain_name|project_name@project_domain_name`
* `username@user_domain_name|project_name` (if project_domain_name = user_domain_name)

Domain scoped user:
* `user_id|@domain_name`
* `user_name@user_domain_name|@domain_name`
 
## Building Exporters

Exporters for Maia are in fact exporters for Prometheus. So the same
[rules and best practises](https://prometheus.io/docs/instrumenting/writing_exporters) should be applied.

On top of this, as explained in the [concept](#concept) chapter, exporters need to provide the `project_id` label as
a prerequisite. Otherwise their metrics are invisible to Maia.

Another aspect that is specific to Maia is the employment of labels. Since Maia is solely used by consumers of metrics -
which are unaware of the data collection process behind -, labels that are not related to the target of the metric should
be omitted. Consequently, labels should be added as needed to qualify/partition the measurements from user
perspective, i.e. specify the _target_ that the measured values relate to. Technical labels such as
`pod_name` or `kubernetes_namespace` that relate only to the inner workings of the exporter should be avoided. They
split the time-series for no good reason and are likely to confuse the consumer.

### Custom Labels

 | Label Key  | Description  |
 |------------|--------------|
 | project_id | OpenStack project UUID |
 | domain_id  | OpenStack domain UUID |
 | service    | OpenStack service key (e.g. `compute`) |
 | server_id  | OpenStack server ID |
 | _\<resource-type\>_\_id | OpenStack ID for _\<resource-type\>_\* |
 | _\<resource-type\>_\_name | OpenStack name for _\<resource-type\>_\* |
 
\* where _\<resource-type\>_ is one of `server`, `network`, `image`, `subnet_pool`, ... i.e. the OpenStack resource type
name that prefixes any OpenStack CLI command.

Whenever possible standard labels should be used. Custom labels should be specific enough not to be confused with
other labels from other metrics. Federation from Prometheus into the Maia-Prometheus is much easier when labels like
`type`, `name` or `system` are avoided.

## Contributing

This project is open for external contributions. The issue list shows what is planned for upcoming releases.

Pull-requests are welcome as long as you follow a few rules:
* Keep the API compatible to Prometheus
* Do not degrade performance
* Include unit tests for new or modified code
* Pass the static code checks
* Keep the architecture intact, don't add shortcuts, layers, ...

## Software Design

Goals of the Maia service:
* Add a multi-tenant security model to Prometheus non-intrusively
  - with OpenStack being the first _driver_ in an otherwise pluggable architecture
* Maintain API compatibility to Prometheus to reuse clients

Components/Packages
* api: Implementation of the API
* cmd: Implementation of the CLI
* keystone: authentication plugin(s)
* prometheus: glue code to attach to a Prometheus as storage

The latter packages will probably be renamed if we decide to support additional user
management services or other monitoring backends (e.g. project cortex).

![Architecture diagram](./maia-architecture.png)

## Links

[![Build Status](https://travis-ci.org/sapcc/maia.svg?branch=master)](https://travis-ci.org/sapcc/maia)
[![Coverage Status](https://coveralls.io/repos/github/sapcc/maia/badge.svg?branch=master)](https://coveralls.io/github/sapcc/maia?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/sapcc/maia)](https://goreportcard.com/report/github.com/sapcc/maia)
[![GoDoc](https://godoc.org/github.com/sapcc/maia?status.svg)](https://godoc.org/github.com/sapcc/maia)

