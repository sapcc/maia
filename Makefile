PKG    = github.com/sapcc/maia
PREFIX := /usr

all: clean build check

GO_BUILDFLAGS :=
GO_LDFLAGS    := -s -w

# This target uses the incremental rebuild capabilities of the Go compiler to speed things up.
# If no source files have changed, `go install` exits quickly without doing anything.
build: FORCE
	glide install -v
	go build $(GO_BUILDFLAGS) -ldflags '-s -w -linkmode external' -o ./maia
	go install $(GO_BUILDFLAGS) -ldflags '$(GO_LDFLAGS)' '$(PKG)'

# which packages to test with static checkers?
GO_ALLPKGS := $(PKG) $(shell go list $(PKG)/pkg/...)
# which packages to test with `go test`?
GO_TESTPKGS := $(shell go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' $(PKG)/pkg/...)
# which packages to measure coverage for?
GO_COVERPKGS := $(shell go list $(PKG)/pkg/... | grep -v plugins)
# output files from `go test`
GO_COVERFILES := $(patsubst %,%.cover.out,$(subst /,_,$(GO_TESTPKGS)))

# down below, I need to substitute spaces with commas; because of the syntax,
# I have to get these separators from variables
space := $(null) $(null)
comma := ,

check: static-check cover.html FORCE
	@echo -e "\e[1;32m>> All tests successful.\e[0m"
static-check: FORCE
	@if s="$$(gofmt -s -l *.go pkg 2>/dev/null)"                            && test -n "$$s"; then printf ' => %s\n%s\n' "gofmt -s -d -e" "$$s"; false; fi
	@if s="$$(golint . && find pkg -type d -exec golint {} \; 2>/dev/null)" && test -n "$$s"; then printf ' => %s\n%s\n' golint "$$s"; false; fi
	go vet $(GO_ALLPKGS)
%.cover.out: FORCE
	go test $(GO_BUILDFLAGS) -ldflags '$(GO_LDFLAGS)' -coverprofile=$@ -covermode=count -coverpkg=$(subst $(space),$(comma),$(GO_COVERPKGS)) $(subst _,/,$*)
cover.out: $(GO_COVERFILES)
	pkg/test/util/gocovcat.go $(GO_COVERFILES) > $@
cover.html: cover.out
	go tool cover -html $< -o $@

install: FORCE all
	install -D -m 0755 ./maia "$(DESTDIR)$(PREFIX)/bin/maia"

clean: FORCE
	rm -f -- ./maia_*_*
	rm -rf vendor

docker.tar: clean
	glide cc
	glide install -v
	docker run --rm -v "$$PWD":"/go/src/github.com/sapcc/maia" -w "/go/src/github.com/sapcc/maia" -e "GOPATH=/go" golang:1.8 env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-s -w -linkmode external -extldflags -static' -o maia_linux_amd64
	tar cf - ./maia_linux_amd64 > build/docker.tar

DOCKER       := docker
DOCKER_IMAGE := hub.global.cloud.sap/monsoon/maia
DOCKER_TAG   := latest

docker: docker.tar
	$(DOCKER) build -t "$(DOCKER_IMAGE):$(DOCKER_TAG)" .

vendor: FORCE
	glide update -v

.PHONY: FORCE
