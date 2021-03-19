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
    MINOR=3
endif
ifndef PATCH
    PATCH=0
endif
ifndef NOTES
	NOTES=
endif
ifndef TAGMSG
    TAGMSG="CSI Spec 1.2"
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
	go generate ./cmd/csi-powerstore
	go run core/semver/semver.go -f mk >semver.mk
	make -f docker.mk DOCKER_FILE=docker-files/$(DOCKER_FILE) docker

# Pushes container to the repository
push:	docker
		make -f docker.mk push

check:	gosec
	gofmt -w ./.
	golint -set_exit_status ./.
	go vet ./...

mocks:
	mockery

test:
	go clean -cache; cd ./pkg; go test -race -cover -coverprofile=coverage.out -coverpkg ./... ./...

coverage:
	cd ./pkg; go tool cover -html=coverage.out -o coverage.html

gosec:
	gosec -quiet -log gosec.log -out=gosecresults.csv -fmt=csv ./...
