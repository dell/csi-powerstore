package e2e

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/dell/csi-powerstore/pkg/common"
	"github.com/dell/gopowerstore"
	"k8s.io/apimachinery/pkg/util/rand"
)

var NameSpaceForEASuite = "ea-ns-"

type ExternalAccessParam struct {
	// tagging with omitempty tag
	Endpoint         string
	UserName         string // `mapstructure:"UserName"`
	Password         string // `mapstructure:"Password"`
	ExternalAccessIP string
}

func ExternalAccessSuite(externalAccess *ExternalAccessParam) error {
	SetNameSpace()

	_, err := exec.Command("bash", "run.sh", "createNameSpace", GetNameSpace()).Output()
	if err != nil {
		return err
	}
	// create NFS SC
	_, err = exec.Command("bash", "run.sh", "createNFSSC", GetNameSpace()).Output()
	if err != nil {
		return err
	}

	// create PVC
	_, err = exec.Command("bash", "run.sh", "createNFSPVC", GetNameSpace()).Output()
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	// create 10 pods
	_, err = exec.Command("bash", "run.sh", "createDeployment", GetNameSpace(), "10").Output()
	if err != nil {
		return err
	}

	// scaledown to 1 pod
	_, err = exec.Command("bash", "run.sh", "createDeployment", GetNameSpace(), "1").Output()
	if err != nil {
		return err
	}

	clientOptions := gopowerstore.NewClientOptions()
	clientOptions.SetInsecure(true)
	clientForArray, err := gopowerstore.NewClientWithArgs(
		externalAccess.Endpoint, externalAccess.UserName, externalAccess.Password, clientOptions)
	if err != nil {
		return err
	}

	ctx := context.Background()
	// PV name
	var pvName string

	out, err := exec.Command("bash", "run.sh", "getPVName", GetNameSpace()).Output()
	if err != nil {
		return err
	}

	pvName = strings.ReplaceAll((string(out)), "\n", "")

	nfsExport, err := clientForArray.GetNFSExportByName(ctx, pvName)
	if err != nil {
		return err
	}

	if !common.ExternalAccessAlreadyAdded(nfsExport, externalAccess.ExternalAccessIP) {
		log.Println("ExteranlAccess should be present in HostAccessList on array")
		return err
	}

	// scaledown to 0 pod
	_, err = exec.Command("bash", "run.sh", "createDeployment", GetNameSpace(), "0").Output()
	if err != nil {
		return err
	}
	// even after deletin all the pods this NFS export should exist
	// since we have not deleted the PVC yet
	nfsExport, err = clientForArray.GetNFSExportByName(ctx, pvName)
	if err != nil {
		return err
	}

	// NFSExport will contain the ExternalAccessIP
	if !common.ExternalAccessAlreadyAdded(nfsExport, externalAccess.ExternalAccessIP) {
		log.Println("ExteranlAccess should be present in HostAccessList on array")
		return err
	}

	// Delete PVCs
	_, err = exec.Command("bash", "run.sh", "deletePvcs", GetNameSpace()).Output()
	if err != nil {
		return err
	}

	nfsExport, err = clientForArray.GetNFSExportByName(ctx, pvName)
	// either this API will throw error or the hostaccesslist should be empty
	// we will check if externalaccess is present or not, it should not be present
	if err == nil && common.ExternalAccessAlreadyAdded(nfsExport, externalAccess.ExternalAccessIP) {
		return err
	}

	return nil
}

func CleanNameSpace(nameSpace string) {
	out, err := exec.Command("bash", "run.sh", "cleanUpNamespace", nameSpace).Output()
	if err != nil {
		fmt.Println(string(out))
	}
}

func SetNameSpace() {
	rand.Seed(time.Now().Unix())
	NameSpaceForEASuite += rand.String(5)
}

func GetNameSpace() string {
	return NameSpaceForEASuite
}
