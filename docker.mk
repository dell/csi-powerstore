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

# Includes the following generated file to get semantic version information
include semver.mk
ifdef NOTES
	RELNOTE="$(NOTES)"
else
	RELNOTE=
endif

ifndef DOCKER_REGISTRY
	DOCKER_REGISTRY=dellemc
endif

ifndef DOCKER_IMAGE_NAME
    DOCKER_IMAGE_NAME=csi-powerstore
endif

# set the GOVERSION
export GOVERSION="1.21"

# Add 'build-base-image' as a dependency if UBI Micro is used as the base image.
# This is required to load all the depedent packages into UBI Miro image.
ifeq ($(DOCKER_FILE), docker-files/Dockerfile.ubi.micro)
	DEPENDENCIES=build-base-image
endif

# figure out if podman or docker should be used (use podman if found)
ifneq (, $(shell which podman 2>/dev/null))
	BUILDER=podman
else
	BUILDER=docker
endif

docker: $(DEPENDENCIES)
	@echo "MAJOR $(MAJOR) MINOR $(MINOR) PATCH $(PATCH) RELNOTE $(RELNOTE) SEMVER $(SEMVER)"
	@echo "$(DOCKER_FILE)"
	$(BUILDER) build -f $(DOCKER_FILE) -t "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):v$(MAJOR).$(MINOR).$(PATCH)$(RELNOTE)" --build-arg BASEIMAGE=$(BASEIMAGE) --build-arg GOVERSION=$(GOVERSION) .


docker-no-cache: $(DEPENDENCIES)
	@echo "MAJOR $(MAJOR) MINOR $(MINOR) PATCH $(PATCH) RELNOTE $(RELNOTE) SEMVER $(SEMVER)"
	@echo "$(DOCKER_FILE) --no-cache"
	$(BUILDER) build --no-cache -f $(DOCKER_FILE) -t "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):v$(MAJOR).$(MINOR).$(PATCH)$(RELNOTE)" --build-arg BASEIMAGE=$(BASEIMAGE) --build-arg GOVERSION=$(GOVERSION) .

push:   
	echo "MAJOR $(MAJOR) MINOR $(MINOR) PATCH $(PATCH) RELNOTE $(RELNOTE) SEMVER $(SEMVER)"
	$(BUILDER) push "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):v$(MAJOR).$(MINOR).$(PATCH)$(RELNOTE)"

build-base-image: download-csm-common
	$(eval include csm-common.mk)
	@echo "Building base image from $(DEFAULT_BASEIMAGE) and loading dependencies..."
	./buildubimicro.sh $(DEFAULT_BASEIMAGE)
	@echo "Base image build: SUCCESS"
	$(eval BASEIMAGE=localhost/csipowerstore-ubimicro:latest)

download-csm-common:
	curl -O -L https://raw.githubusercontent.com/dell/csm/main/config/csm-common.mk
