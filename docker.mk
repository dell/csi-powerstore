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

ifndef DOCKER_FILE
    DOCKER_FILE=Dockerfile
endif

docker:
	echo "MAJOR $(MAJOR) MINOR $(MINOR) PATCH $(PATCH) BUILD $(BUILD) RELNOTE $(RELNOTE) SEMVER $(SEMVER)"
	docker build -f $(DOCKER_FILE) -t "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):v$(MAJOR).$(MINOR).$(PATCH).$(BUILD)$(RELNOTE)" .

push:   
	echo "MAJOR $(MAJOR) MINOR $(MINOR) PATCH $(PATCH) BUILD $(BUILD) RELNOTE $(RELNOTE) SEMVER $(SEMVER)"
	docker push "$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):v$(MAJOR).$(MINOR).$(PATCH).$(BUILD)$(RELNOTE)"
