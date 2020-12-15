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
    DOCKER_REGISTRY=
endif

ifndef DOCKER_IMAGE_NAME
    DOCKER_IMAGE_NAME=csi_powerstore
endif

ifndef BASEIMAGE
	BASEIMAGE=centos:8
endif

# figure out if podman or docker should be used (use podman if found)
ifneq (, $(shell which podman 2>/dev/null))
	BUILDER=podman
else
	BUILDER=docker
endif

docker:
	echo "MAJOR $(MAJOR) MINOR $(MINOR) PATCH $(PATCH) BUILD $(BUILD) RELNOTE $(RELNOTE) SEMVER $(SEMVER)"
	echo "$(DOCKER_FILE)"
	$(BUILDER) build -f $(DOCKER_FILE) -t "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):v$(MAJOR).$(MINOR).$(PATCH).$(BUILD)$(RELNOTE)" --build-arg BASEIMAGE=$(BASEIMAGE) .

push:   
	echo "MAJOR $(MAJOR) MINOR $(MINOR) PATCH $(PATCH) BUILD $(BUILD) RELNOTE $(RELNOTE) SEMVER $(SEMVER)"
	$(BUILDER) push "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):v$(MAJOR).$(MINOR).$(PATCH).$(BUILD)$(RELNOTE)"
