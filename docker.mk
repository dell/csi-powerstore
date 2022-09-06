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

ifndef BASEIMAGE
	BASEIMAGE=ubi-minimal:8.6-902.1661794353
endif

# figure out if podman or docker should be used (use podman if found)
ifneq (, $(shell which podman 2>/dev/null))
	BUILDER=podman
else
	BUILDER=docker
endif

docker:
	echo "MAJOR $(MAJOR) MINOR $(MINOR) PATCH $(PATCH) RELNOTE $(RELNOTE) SEMVER $(SEMVER)"
	echo "$(DOCKER_FILE)"
	$(BUILDER) build -f $(DOCKER_FILE) -t "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):v$(MAJOR).$(MINOR).$(PATCH)$(RELNOTE)" --build-arg BASEIMAGE=$(BASEIMAGE) .

docker-no-cache:
	echo "MAJOR $(MAJOR) MINOR $(MINOR) PATCH $(PATCH) RELNOTE $(RELNOTE) SEMVER $(SEMVER)"
	echo "$(DOCKER_FILE) --no-cache"
	$(BUILDER) build --no-cache --pull -f $(DOCKER_FILE) -t "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):v$(MAJOR).$(MINOR).$(PATCH)$(RELNOTE)" --build-arg BASEIMAGE=$(BASEIMAGE) .


push:   
	echo "MAJOR $(MAJOR) MINOR $(MINOR) PATCH $(PATCH) RELNOTE $(RELNOTE) SEMVER $(SEMVER)"
	$(BUILDER) push "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):v$(MAJOR).$(MINOR).$(PATCH)$(RELNOTE)"
