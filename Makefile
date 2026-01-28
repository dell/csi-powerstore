# Copyright © 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Dell Technologies, Dell and other trademarks are trademarks of Dell Inc.
# or its subsidiaries. Other trademarks may be trademarks of their respective 
# owners.

include images.mk

all: help

# This will be overridden during image build.
IMAGE_VERSION ?= 0.0.0
LDFLAGS = "-X main.ManifestSemver=$(IMAGE_VERSION)"

# Help target, prints usefule information
help:
	@echo
	@echo "The following targets are commonly used:"
	@echo
	@echo "build            - Builds the code locally"
	@echo "check            - Runs the suite of code checking tools: lint, format, etc"
	@echo "clean            - Cleans the local build"
	@echo "images           - Builds the code within a golang container and then creates the driver image"
	@echo "push             - Pushes the built container to a target registry"
	@echo "unit-test        - Runs the unit tests"
	@echo "vendor           - Downloads a vendor list (local copy) of repositories required to compile the repo."

clean:
	rm -f semver.mk core/core_generated.go
	rm -rf vendor
	rm -f csi-powerstore
	go clean -cache

build: generate vendor
	GOOS=linux CGO_ENABLED=0 go build -mod=vendor -ldflags $(LDFLAGS) ./cmd/csi-powerstore

mocks:
	mockery

unit-test: go-code-tester
	GITHUB_OUTPUT=/dev/null \
	./go-code-tester 90 "." "" "true" "" "" "./mocks|./v2/core|./tests|./replace"

test:
	cd ./pkg; go test -race -cover -coverprofile=coverage.out ./...

coverage:
	cd ./pkg; go tool cover -html=coverage.out -o coverage.html

go-code-tester:
	git clone --depth 1 git@github.com:CSM/actions.git temp-repo
	cp temp-repo/go-code-tester/entrypoint.sh ./go-code-tester
	chmod +x go-code-tester
	rm -rf temp-repo
