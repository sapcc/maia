<!--
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company

SPDX-License-Identifier: Apache-2.0
-->

# Maia Users Guide

[Maia UI](#using-the-maia-ui)

* Prometheus expression browser adapted to Maia
* Browse projects and metrics
* Perform ad-hoc PromQL queries
* Graph metrics

[Maia CLI](#using-the-maia-client)

* Feature-complete CLI supporting all API operations
* JSON and Go-template-based output for reliable automation
* Works with Prometheus, too (no OpenStack required)

## Using the Maia UI

Maia comes with a [PromQL Expression Browser](https://prometheus.io/docs/visualization/browser/) borrowed from
Prometheus.

You can use it to discover metrics, series and perform ad-hoc queries leveraging all of PromQL's rich query syntax.

### Login

Just log-on using your OpenStack credentials.

```
URL: https://maia.myopenstack.net/myUserDomain
Username: myUser
Password: ********
```

Maia will choose a project for you. You can switch to any other project via the dropdown menu on the top-right side.

Instead of adding the name of the user-domain (e.g. `myUserDomain`) to the URL, you may also specify it as part of
the username, when the browser prompts for your credentials.

```
Username: myUser@myUserDomain
Password: ******
```

If you neither specify the user-domain in the username nor the URL, Maia will assume that the user is part
of the configured default domain (not to be confused with the OpenStack domain `default`).

```
URL: https://maia.myopenstack.net
Username: myUser
```

You may also use the special username syntax described in more detail [here](#openstack-authentication-and-authorization)
to log right into your target project.

```
Username: myuser@mydomain|myproject@mydomain
Password: ********
```

Or you use OpenStack _application credentials_:

```
# this is an example of ID-based login
username: *myappcredid
password: myappcredsecret
# this is an example of name-based login
username: *myappcredname@myuser@mydomain
password: myappcredsecret
```

### The Maia Screen

The Maia screen consists of three part:

* Navigation area (top)
* PromQL query input field with metrics dropdown list
* Result area with two tabs:
  - Graph area for visualizing the query result
  - Console area listing the different _series_ produced by the query

### Discover Metrics

You can use the dropdown list or the auto-completion functionality of the PromQL input field to discover which
metrics are known by the system.

```
openstack_compute_instances_gauge
```

Once you hit `<enter>`, Maia will provide you a list of all known time series for that metric in the `Console` area.

Usually this list is quite long. So you should restrict your query further by adding constraints about the labels
in curly braces. In Prometheus terminology, these constraints are called _selectors_

```
openstack_compute_instances_gauge{vm_state="active"}
```

### Visualize Series

Once you have restricted the number of series to a feasible amount, you may go ahead and graph them.

For that you just click on the `Graph` tab left from the `Console` one.

The displayed line graph shows the historical metric values within the selected timeframe.

You can use the following controls to adjust the graph:

* `-`/`+` can be used to reduce/extend the timeframe

* `<<`/`>>`can be used to shift the timeframe back resp. forth in time

* `Res. (s)` can be used to change the resolution i.e. adjust the size of a data point in seconds (e.g. enter `300s`
to get one cumulative value for each 5 minute interval)

## Using the Maia Client

The `maia` command can also be used to retrieve metrics from the Maia service. It behaves like any other OpenStack
 CLI, supporting the same command line options and environment variables for authentication:

| Option | Environment Variable | Description |
|:--------:|:----------------------:|:-------------:|
| --os-username | OS_USERNAME | OpenStack username, requires `os-user-domain-name` |
| --os-user-id | OS_USER_ID | OpenStack user unique ID |
| --os-password | OS_PASSWORD | Password |
| --os-token | OS_TOKEN | Pregenerated Keystone token with authorization scope |
| --os-application-credential-id | OS_APPLICATION_CREDENTIAL_ID | ID of an _application credential_ |
| --os-application-credential-name | OS_APPLICATION_CREDENTIAL_NAME | name of an _application credential_, scoped by user |
| --os-application-credential-secret | OS_APPLICATION_CREDENTIAL_SECRET | secret of an _application credential_ |
| --os-user-domain-name | OS_USER_DOMAIN_NAME | domain name, qualifying the username (default: `Default`) |
| --os-user-domain-id | OS_USER_DOMAIN_ID | domain unique ID, qualifying the username (default: `default`) |
| --os-project-name | OS_PROJECT_NAME | OpenStack project name for authorization scoping to project, requires `os-project-domain-name` |
| --os-project-id | OS_PROJECT_ID | OpenStack project unique ID |
| --os-domain-name | OS_DOMAIN_NAME | OpenStack domain name for authorization scoping to domain |
| --os-domain-id | OS_DOMAIN_ID | OpenStack domain unique ID for authorization scoping to domain |
| --os-auth-url | OS_AUTH_URL | Endpoint of the Identity v3 service. Needed to authentication and Maia endpoint lookup |
| --os-auth-type | OS_AUTH_TYPE | Authentication method to use: one of `password`, `token`, `v3applicationcredential`|

Usually, you can reuse your existing RC-files. For performance reasons, you should consider token-based
authentication whenever you make several calls to the Maia CLI.

Use `openstack token issue` to generate a token and pass it to the Maia CLI in the `OS_TOKEN` variable.

```
export OS_TOKEN=$(openstack token issue -c id -f value)
```

If for some reason you want to use another Maia endpoint than the one registered in the OpenStack service catalog,
then you can override its URL using the `--maia-url` option:

| Option | Environment Variable | Description |
|:--------:|:----------------------:|:-------------:|
| --maia-url | MAIA_URL | URL of the Maia service endpoint |

In the examples below we assume that you have initialized the OS_* variables your shell environment properly and that
your user has the prerequisite roles (e.g. `monitoring_viewer`) on the project in scope.

Type `maia --help` to get a full list of commands and options options with documentation.

```
maia --help
```

### Show Known Measurement Series

Use the `series` command to get a list of all measurement series. You can restrict the timeframe using
the parameters `--start` and `--end`.

```
maia series --selector "__name__=~'vc.*'" --start '2017-07-26T10:46:25+02:00'
```

The list of series can be filtered using Prometheus label matchers. Don't forget to put it in quotes.
```
maia snapshot --selector 'job="endpoints"' ...
```

### List Known Metric Names

Use the `metric-names` command to obtain a list of metric names.

```
maia metric-names
```

### List Known Label Values

Use the `label-values` command to obtain known values for a given label.

```
maia label-values "job"
```

Note that stale series which did not receive measurements recently may not be considered for this list.

### Query Metrics with PromQL

Use the `query` command to perform an arbitrary [PromQL-query](https://prometheus.io/docs/querying/basics/) against Maia.
It returns a single entry for each series. This is called an _instant query_.

```
maia query 'vcenter_virtualDisk_totalWriteLatency_average{vmware_name:"win_cifs_13"}'
```

Older values can be obtained using the `--time` parameter.

```
maia query ... --time 2017-07-01T05:10:51.781Z
```

Finally you can extract all values during a given timeframe by specifying a start- and end-date with the `--start` resp.
`--end` parameters. This is called a _range query_.

You should also specify the resolution using the `--stepsize` parameter. Otherwise
Maia will choose defaults that may not always fit well. Timestamps can be specified in Unix or RC3339 format. Durations are
specififed as numbers with a unit suffix, such as `30s`, `1.5h` or `2h45m`. Valid time units are `ns`, `us`,
`ms`, `s`, `m`, `h`.

```
maia query ... --start 2017-07-01T05:10:51.781Z --end 2017-07-01T09:10:51.781Z --stepsize 300s
```

Also be aware that due to the sheer amount of data, range query results usually do not fit the width of a terminal screen.
For that reason the default output format for _range queries_ is `json` and not `table`. Keep this in mind when you want to
do a CSV export to a speadsheet.

Enter `maia query --help` for more options.

### Output Formatting

By default maia prints results as unformatted text. Series data is formatted in raw tables without column alignment.
Labels are used as columns (alphabetical sorting). There are three additional columns which do not refer
to labels:

| Column Name | Meaning |
|:-------------:|:---------:|
| \_\_name\_\_ | the metric name |
| \_\_timestamp\_\_ |  the timestamp of a measurement |
| \_\_value\_\_ | the value of a measurement |

To enable automation, also JSON, plain values output and Go text-templates
are supported.

The output is controlled via the parameters `--format`, `--columns`, `--separator`and `--template`.

| Format   | Description | Additional Options                                                              |
|:----------:|:-------------:|:---------------------------------------------------------------------------------:|
| table | text output in tabular form | `--columns`: selects which metric-labels are displayed as columns<br>`--separator`: defines how columns are separated        |
| value | output of plain values in lists or tables | like `table`                                          |
| json     | JSON output of Maia/Prometheus server. Contains additional status/error information. See [Prometheus API doc.](https://prometheus.io/docs/querying/api/#expression-query-result-formats) | none |
| template | Highly configurable output, applying [Go-templates](https://golang.org/pkg/text/template/) to the JSON response (see `json`format) | `--template`: Go-template expression |

### Exporting Snapshots

Use the `snapshot` command to get the latest values of all series in
[textual form](https://prometheus.io/docs/instrumenting/exposition_formats/).

```
maia snapshot
```

The amount of data can be restricted using Prometheus label matchers, i.e. constraints on label values:

```
maia snapshot --selector 'job="endpoints"' ...
```

If you want to preprocess/filter data further, you can e.g. use the [prom2json](https://github.com/prometheus/prom2json)
tool together with [jq](https://github.com/stedolan/jq).

### Use Maia Client with Prometheus

You can also use the maia client with a plain Prometheus (no authentication).

```
maia snapshot --prometheus-url http://localhost:9090
```

## Using Maia with Grafana

Due to its API-compatibility, the Prometheus data source in Grafana can be used for Maia as well. That means you can
build elaborate dashboards around Maia metrics with your existing Grafana installation. No additional plugins needed!

Configure the data source like with a regular Prometheus. Select `Basic Authentication` and enter the scoped
 user credentials.

There are several variants to express the project/domain scope:

Project scoped user:

* `user_id|project_id`
* `username@user_domain_name|project_id`
* `user_id|project_name@project_domain_name`
* `username@user_domain_name|project_name@project_domain_name`
* `username@user_domain_name|project_name` (if project_domain_name = user_domain_name)

Domain scoped user:

* `user_id|@domain_name`
* `user_name@user_domain_name|@domain_name`

Application Credential:

* `*app_cred_id`
* `*app_cred_name@user_id`
* `*app_cred_name@user_name@user_domain_name`

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

Alternatively, OpenStack _application credentials_ can be used in place of username and password. With these credentials you are implicitly scoped
to a single project (or domain), so there is no need to supply scope information as before.

To tell Maia that the username and password fields are actually containing _application credentials_,
you put an asterisk (`*`) in front of the username value.

There are two ways to authenticate with application credentials:
* ID-based: Use the application credential ID as username
* Name-based: Use the application credential name and qualify it using the username or user ID

In both cases you use the _secret_ of the application credential as password.

# Federating Maia to Prometheus

To configure Prometheus to receive data from Maia, the following job configuration has to be applied.

In the `basic_auth` section a valid user id, project id and password, corresponding to your OpenStack User and Project,
has to be provided. For convenience you can always use the `user_name@user_domain_name` syntax instead of the technical IDs.

The user is required to have the `metric:show` permission.

```yaml
scrape_configs:

  # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
  - job_name: 'maia'
    metrics_path: "/federate"
    basic_auth:
      # Corresponds to your OpenStack User and Project
    username: <user_name>@<user_domain_name>|<project_name>@<project_domain_name>  # or <user_id>|<project_id>
    password: <password>

    static_configs:
      - targets: ['maia.<region>.cloud.sap:443']

```

Prometheus' targets page ( Status -> Targets ) should the new job and the endpoint with `State UP`.
The `Error` column should be empty.
It might indicate a failed authorization (`401 Unauthorized`).
