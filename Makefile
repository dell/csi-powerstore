#
#
# Copyright © 2020-2025 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#      http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#

# for variables override
-include vars.mk

all: clean build

# Tag parameters
ifndef TAGMSG
    TAGMSG="CSI Spec 1.6"
endif

clean:
	rm -f core/core_generated.go
	rm -f semver.mk
	go clean

build:
	go generate ./cmd/csi-powerstore
	GOOS=linux CGO_ENABLED=0 go build ./cmd/csi-powerstore

dev-docker: build
	docker build -t csi-powerstore-hbn -f dev-docker-file --network host .
	docker images | head -10

install:
	go generate ./cmd/csi-powerstore
	GOOS=linux CGO_ENABLED=0 go install ./cmd/csi-powerstore

# Tags the release with the Tag parameters set above
tag:
	go run core/semver/semver.go -f mk >semver.mk
	make -f docker.mk tag TAGMSG='$(TAGMSG)'

# Generates the docker container (but does not push)
docker:
	go run core/semver/semver.go -f mk >semver.mk
	make -f docker.mk docker

# Same as `docker` but without cached layers and will pull latest version of base image
docker-no-cache:
	go run core/semver/semver.go -f mk >semver.mk
	make -f docker.mk docker-no-cache

# Pushes container to the repository
push:	docker
		make -f docker.mk push

check:	gosec
	gofmt -w ./.
ifeq (, $(shell which golint))
	go install golang.org/x/lint/golint@latest
endif
	golint -set_exit_status ./.
	go vet ./...

mocks:
	mockery

test:
	go clean -cache; cd ./pkg; go test -race -cover -coverprofile=coverage.out ./...

coverage:
	cd ./pkg; go tool cover -html=coverage.out -o coverage.html

gosec:
ifeq (, $(shell which gosec))
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	$(shell $(GOBIN)/gosec -quiet -log gosec.log -out=gosecresults.csv -fmt=csv ./...)
else
	$(shell gosec -quiet -log gosec.log -out=gosecresults.csv -fmt=csv ./...)
endif
	@echo "Logs are stored at gosec.log, Outputfile at gosecresults.csv"


.PHONY: actions action-help
actions: ## Run all GitHub Action checks that run on a pull request creation
	@echo "Running all GitHub Action checks for pull request events..."
	@act -l | grep -v ^Stage | grep pull_request | grep -v image_security_scan | awk '{print $$2}' | while read WF; do \
		echo "Running workflow: $${WF}"; \
		act pull_request --no-cache-server --platform ubuntu-latest=ghcr.io/catthehacker/ubuntu:act-latest --job "$${WF}"; \
	done

action-help: ## Echo instructions to run one specific workflow locally
	@echo "GitHub Workflows can be run locally with the following command:"
	@echo "act pull_request --no-cache-server --platform ubuntu-latest=ghcr.io/catthehacker/ubuntu:act-latest --job <jobid>"
	@echo ""
	@echo "Where '<jobid>' is a Job ID returned by the command:"
	@echo "act -l"
	@echo ""
	@echo "NOTE: if act is not installed, it can be downloaded from https://github.com/nektos/act"
