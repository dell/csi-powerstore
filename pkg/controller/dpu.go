package controller

import (
	"github.com/container-storage-interface/spec/lib/go/csi"
	log "github.com/sirupsen/logrus"
)

func AddVolumeToDPU(volume *csi.Volume) error {
	log.Info(volume)
	// call goopcsi createVolume equivalent API here
	return nil
}

func DeleteVolumeFromDPU(volume *csi.Volume) error {
	log.Info(volume)
	// call goopcsi deleteVolume equivalent API here
	return nil
}
