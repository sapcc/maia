OS := $(shell uname -s)
UID := $(shell id -u)
PKG = github.com/sapcc/maia
PREFIX := /usr
PWD := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

GO_BUILDFLAGS :=
GO_LDFLAGS    := -s -w
ifdef DEBUG
	BINDDATA_FLAGS = -debug
endif

DOCKER       := docker
DOCKER_IMAGE := hub.global.cloud.sap/monsoon/maia
DOCKER_TAG   := latest

# which packages to test with static checkers?
GO_ALLPKGS := $(PKG) $(shell go list $(PKG)/pkg/...)
# which packages to test with `go test`?
GO_TESTPKGS := $(shell go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' $(PKG)/pkg/...)
# which packages to measure coverage for?
GO_COVERPKGS := $(shell go list $(PKG)/pkg/... | grep -v plugins)
# output files from `go test`
GO_COVERFILES := $(patsubst %,build/%.cover.out,$(subst /,_,$(GO_TESTPKGS)))

# force using the vendor directory
export GO111MODULE=off
export GOPATH := $(PWD)/.gopath
export PATH := $(PATH):$(GOPATH)/bin

all: clean build check

# This target uses the incremental rebuild capabilities of the Go compiler to speed things up.
# If no source files have changed, `go install` exits quickly without doing anything.
generate: FORCE
	# generate mocks
	mockgen --source $(GOPATH)/src/$(PKG)/pkg/storage/interface.go --destination $(GOPATH)/src/$(PKG)/pkg/storage/genmock.go --package storage
	mockgen --source $(GOPATH)/src/$(PKG)/pkg/keystone/interface.go --destination $(GOPATH)/src/$(PKG)/pkg/keystone/genmock.go --package keystone
	# generate UI
	go-bindata $(BINDDATA_FLAGS) -pkg ui -o pkg/ui/bindata.go -ignore '(.*\.map|bootstrap\.js|bootstrap-theme\.css|bootstrap\.css)' web/templates/... web/static/...
	gofmt -s -w ./pkg/ui/bindata.go
	# fix generated code comment in order to be respected by golint
	sed -i.bak  's,// Code generated by go-bindata\.$$,// Code generated by go-bindata. DO NOT EDIT.,g' pkg/ui/bindata.go

build: dependencies generate
	# build maia
	go build $(GO_BUILDFLAGS) -ldflags '$(GO_LDFLAGS)'
	go install $(GO_BUILDFLAGS) -ldflags '$(GO_LDFLAGS)' '$(PKG)'

docker-build:
	$(DOCKER) run --rm -v "$$PWD":"/maia" -u $(UID):$(UID) -w "/maia" -e GOCACHE=/tmp golang:1.12-stretch make build/platforms

build/platforms: dependencies generate
	GOOS=linux GOARCH=amd64 go build -a -ldflags '$(GO_LDFLAGS)' -o bin/maia_linux_amd64
	GOOS=darwin GOARCH=amd64 go build -a -ldflags '$(GO_LDFLAGS)' -o bin/maia_darwin_amd64
	GOOS=windows GOARCH=amd64 go build -a -ldflags '$(GO_LDFLAGS)' -o bin/maia_windows_amd64.exe

.gopath/src/$(PKG):
	mkdir -p .gopath/src/$(shell dirname $(PKG))
	ln -sf ../../../.. .gopath/src/$(PKG)

# down below, I need to substitute spaces with commas; because of the syntax,
# I have to get these separators from variables
space := $(null) $(null)
comma := ,

check: static-check build/cover.html
	@echo -e "\e[1;32m>> All tests successful.\e[0m"

static-check: FORCE .gopath/src/$(PKG)
	go get golang.org/x/lint/golint
	@if s="$$(gofmt -s -l *.go pkg 2>/dev/null)"                            && test -n "$$s"; then printf ' => %s\n%s\n' gofmt -s -d -e "$$s"; false; fi
	@if s="$$(golint . && find pkg -type d -exec golint {} \; 2>/dev/null)" && test -n "$$s"; then printf ' => %s\n%s\n' golint "$$s"; false; fi
	go vet $(GO_ALLPKGS)

build/%.cover.out:
	# echo "testing packages $(GO_COVERPKGS)"
	go test $(GO_BUILDFLAGS) -ldflags '$(GO_LDFLAGS)' -coverprofile=$@ -covermode=count -coverpkg=$(subst $(space),$(comma),$(GO_COVERPKGS)) $(subst _,/,$*)

build/cover.out: $(GO_COVERFILES)
	# echo "merge coverage files for $(GO_COVERFILES)"
	pkg/test/util/gocovcat.go $(GO_COVERFILES) > $@

build/cover.html: build/cover.out
	go tool cover -html $< -o $@

install: all
	install -D -m 0755 maia "$(DESTDIR)$(PREFIX)/bin/maia"

clean: FORCE
	rm -f build/*
	rm -f -- bin/maia_*_*
	# remove generated mocks
	rm -f pkg/storage/genmock.go
	rm -f pkg/keystone/genmock.go
	rm -f pkg/ui/bindata.go

build/docker.tar: dependencies generate
	GOOS=linux GOARCH=amd64 go build -a -ldflags '$(GO_LDFLAGS)' -o bin/maia_linux_amd64
	tar --strip-components=1 -cf bin/maia_linux_amd64 > build/docker.tar

docker: build/docker.tar
	$(DOCKER) build -t "$(DOCKER_IMAGE):$(DOCKER_TAG)" .

vendor: FORCE .gopath/src/$(PKG)
	GO111MODULE=auto go get -u
	GO111MODULE=auto go mod download
	GO111MODULE=auto go mod tidy
	GO111MODULE=auto go mod vendor

dependencies: .gopath/src/$(PKG)
	go get golang.org/x/tools/go/packages
	go get github.com/golang/mock/gomock
	go install github.com/golang/mock/mockgen
	go get github.com/jteeuwen/go-bindata/...

.PHONY: FORCE
