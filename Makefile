#
#
# Copyright © 2020-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
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

# Dockerfile defines which base image to use [Dockerfile.centos, Dockerfile.ubi, Dockerfile.ubi.min, Dockerfile.ubi.alt]
# e.g.:$ make docker DOCKER_FILE=Dockerfile.ubi.alt
ifndef DOCKER_FILE
    DOCKER_FILE = Dockerfile.ubi.micro
endif

# Tag parameters
ifndef MAJOR
    MAJOR=2
endif
ifndef MINOR
    MINOR=12
endif
ifndef PATCH
    PATCH=0
endif
ifndef NOTES
	NOTES=
endif
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

install:
	go generate ./cmd/csi-powerstore
	GOOS=linux CGO_ENABLED=0 go install ./cmd/csi-powerstore

# Tags the release with the Tag parameters set above
tag:
	-git tag -d v$(MAJOR).$(MINOR).$(PATCH)$(NOTES)
	git tag -a -m $(TAGMSG) v$(MAJOR).$(MINOR).$(PATCH)$(NOTES)

# Generates the docker container (but does not push)
docker:
	go run core/semver/semver.go -f mk >semver.mk
	make -f docker.mk DOCKER_FILE=docker-files/$(DOCKER_FILE) docker

# Same as `docker` but without cached layers and will pull latest version of base image
docker-no-cache:
	go run core/semver/semver.go -f mk >semver.mk
	make -f docker.mk DOCKER_FILE=docker-files/$(DOCKER_FILE) docker-no-cache

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
