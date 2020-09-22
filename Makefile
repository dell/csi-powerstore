# for variables override
-include vars.mk

all: clean build

# Dockerfile defines which base image to use [Dockerfile.centos, Dockerfile.ubi, Dockerfile.ubi.min, Dockerfile.ubi.alt]
# e.g.:$ make docker DOCKER_FILE=Dockerfile.ubi.alt
ifndef DOCKER_FILE
    DOCKER_FILE = Dockerfile.centos
endif

# Tag parameters
ifndef MAJOR
    MAJOR=1
endif
ifndef MINOR
    MINOR=1
endif
ifndef PATCH
    PATCH=0
endif
ifndef BUILD
	BUILD=000
endif
ifndef NOTES
    NOTES=R
endif
ifndef TAGMSG
    TAGMSG="CSI Spec 1.2"
endif


clean:
	rm -f core/core_generated.go
	rm -f semver.mk
	go clean

build:
	go generate
	GOOS=linux CGO_ENABLED=0 go build

install:
	go generate
	GOOS=linux CGO_ENABLED=0 go install

# Tags the release with the Tag parameters set above
tag:
	-git tag -d v$(MAJOR).$(MINOR).$(PATCH).$(BUILD)$(NOTES)
	git tag -a -m $(TAGMSG) v$(MAJOR).$(MINOR).$(PATCH).$(BUILD)$(NOTES)

# Generates the docker container (but does not push)
docker:
	go generate
	go run core/semver/semver.go -f mk >semver.mk
	make -f docker.mk DOCKER_FILE=docker-files/$(DOCKER_FILE) docker

# Pushes container to the repository
push:	docker
		make -f docker.mk push

# Windows or Linux; requires no hardware
unit-test:
	( cd service; go clean -cache; go test -race -v -tags="test" -coverprofile=c.out ./... )

test:
	( cd service; go clean -cache;go test -race -v -tags="test godog" -coverprofile=c.out ./...)

godog:
	( cd service; go clean -cache;go test -race -v -tags="godog" -coverprofile=c.out ./...)

gocover:
	cd service; go tool cover -html=c.out

check:	gosec
	gofmt -w ./.
	golint -set_exit_status ./.
	go vet
	(cd service;  go test -tags=test -run TestMock)

mock-gen:
	mockgen -source  service/interfaces.go \
		-self_package github.com/dell/csi-powerstore/service  \
		-destination service/mocks_test.go --package service
	(cd service;  go test -tags=test -run TestMock)

gosec:
	gosec -quiet -log gosec.log -out=gosecresults.csv -fmt=csv ./...
