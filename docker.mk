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

ifeq ($(IMAGETAG),)
IMAGETAG=v$(MAJOR).$(MINOR).$(PATCH)$(RELNOTE)
endif

ifndef DOCKER_REGISTRY
	DOCKER_REGISTRY=dellemc
endif

ifndef DOCKER_IMAGE_NAME
    DOCKER_IMAGE_NAME=csi-powerstore
endif

# set the GOVERSION
export GOVERSION="1.21"

# figure out if podman or docker should be used (use podman if found)
ifneq (, $(shell which podman 2>/dev/null))
	BUILDER=podman
else
	BUILDER=docker
endif

docker: download-csm-common
	$(eval include csm-common.mk)
	$(BUILDER) build --pull -t "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(IMAGETAG)" --build-arg GOIMAGE=$(DEFAULT_GOIMAGE) --build-arg BASEIMAGE=$(CSM_BASEIMAGE) .

docker-no-cache: download-csm-common
	$(eval include csm-common.mk)
	$(BUILDER) build --pull --no-cache -t "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(IMAGETAG)" --build-arg GOIMAGE=$(DEFAULT_GOIMAGE) --build-arg BASEIMAGE=$(CSM_BASEIMAGE) .

push:
	$(BUILDER) push "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(IMAGETAG)"

download-csm-common:
	curl -O -L https://raw.githubusercontent.com/dell/csm/main/config/csm-common.mk

tag:
	-git tag -d $(IMAGETAG)
	git tag -a -m $(TAGMSG) $(IMAGETAG)
