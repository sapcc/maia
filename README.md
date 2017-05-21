# Maia

[![Build Status](https://travis-ci.org/sapcc/maia.svg?branch=master)](https://travis-ci.org/sapcc/maia)
[![Coverage Status](https://coveralls.io/repos/github/sapcc/maia/badge.svg?branch=master)](https://coveralls.io/github/sapcc/maia?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/sapcc/maia)](https://goreportcard.com/report/github.com/sapcc/maia)
[![GoDoc](https://godoc.org/github.com/sapcc/maia?status.svg)](https://godoc.org/github.com/sapcc/maia)

Maia is an OpenStack-compatible service that allows querying Prometheus metrics per OpenStack project or domain.
It was originally designed for the SAP Converged Cloud.

# Design

![Architecture diagram](./docs/maia-architecture.png)

# Installation

Via Makefile

* `make` to just compile and run the binaries from the `build/` directory
* `make && make install` to install to `/usr`
* `make && make install PREFIX=/some/path` to install to `/some/path`
* `make docker` to build the Docker image (set image name and tag with the `DOCKER_IMAGE` and `DOCKER_TAG` variables)
