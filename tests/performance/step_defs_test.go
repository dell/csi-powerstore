/*
 *
 * Copyright © 2020 Dell Inc. or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package performance

import (
	"context"
	"encoding/csv"
	"fmt"
	"github.com/DATA-DOG/godog"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/dell/csi-powerstore/service"
	"github.com/dell/gopowerstore"
	"github.com/joho/godotenv"
	"github.com/rexray/gocsi"
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"
	"time"
)

const (
	EnvVarsFile    = "./features/envvars.sh"
	RetrySleepTime = 1 * time.Second
	SleepTime      = 100 * time.Millisecond
	MaxRetryCount  = 10
)

type feature struct {
	err               error
	errs              []error
	volIDs            []string
	controllerService service.Service
	nodeService       service.Service
	nodeID            string
	ctrlAdmClient     gopowerstore.Client
	nodeAdmClient     gopowerstore.Client
	capability        *csi.VolumeCapability
	publishContexts   []map[string]string
	writer            *csv.Writer
	file              *os.File
}

// aPowerStoreService initialize node and controller PowerStore services
// NOTE: iscsi should be enabled on running machine
// NOTE: initial node init and registering on storage array can take some time
func (f *feature) aPowerStoreService() error {
	f.errs = []error{}
	f.volIDs = []string{}
	f.ctrlAdmClient = nil
	f.nodeAdmClient = nil
	f.capability = nil
	f.controllerService = f.getService("controller", f.ctrlAdmClient)
	f.nodeService = f.getService("node", f.nodeAdmClient)
	f.publishContexts = []map[string]string{}
	nodeInfo, err := f.nodeService.NodeGetInfo(context.Background(), &csi.NodeGetInfoRequest{})
	if err != nil {
		return err
	}
	f.nodeID = nodeInfo.NodeId

	name := fmt.Sprintf("perf-result-%s.csv", time.Now().Format(time.UnixDate))
	file, _ := os.Create(name)
	f.file = file
	f.writer = csv.NewWriter(file)

	return nil
}

// getService creates a service with mode enabled ("node" or "controller")
func (f *feature) getService(mode string, adminClient gopowerstore.Client) service.Service {
	svc := service.NewWithOptions(adminClient)

	err := godotenv.Load(EnvVarsFile)
	if err != nil {
		log.Printf("%s file not found.", EnvVarsFile)
	}

	sp := &gocsi.StoragePlugin{}

	_ = os.Setenv("X_CSI_MODE", mode)
	f.err = svc.BeforeServe(context.Background(), sp, nil)
	return svc
}

// thereAreNoErrors checks that there was no errors
func (f *feature) thereAreNoErrors() error {
	if len(f.errs) == 0 {
		return nil
	}
	return f.errs[0]
}

// writeResults write execution results in STDOUT and in .csv file
func (f *feature) writeResults(method string, nVols, nerrors int, t0, t1 time.Time) {
	fmt.Printf("%s volume time for %d volumes %d errors: %v %v\n", method, nVols, nerrors, t1.Sub(t0).Seconds(), t1.Sub(t0).Seconds()/float64(nVols))
	_ = f.writer.Write([]string{method, strconv.Itoa(nVols), strconv.Itoa(nerrors),
		floatToString(t1.Sub(t0).Seconds()), floatToString(t1.Sub(t0).Seconds() / float64(nVols))})
	f.writer.Flush()
}

func floatToString(inputNum float64) string {
	return strconv.FormatFloat(inputNum, 'f', 5, 64)
}

// iCreateVolumesInParallel creates nVols "create" requests to driver in goroutines
// NOTE: IDs of created volumes are stored inside of feature struct, to be used in later functions
func (f *feature) iCreateVolumesInParallel(nVols int) error {
	idchan := make(chan string, nVols)
	errchan := make(chan error, nVols)
	t0 := time.Now()

	// Send requests
	for i := 0; i < nVols; i++ {
		name := fmt.Sprintf("parallel-perf-%d", i)
		go func(name string, idchan chan string, errchan chan error) {
			var resp *csi.CreateVolumeResponse
			var err error
			req := f.getMountVolumeRequest(name)
			if req != nil {
				resp, err = f.controllerService.CreateVolume(context.Background(), req)
				if resp != nil {
					idchan <- resp.GetVolume().VolumeId
				} else {
					idchan <- ""
				}
			}
			errchan <- err
		}(name, idchan, errchan)
	}
	// Wait on complete, collecting ids and errors
	nerrors := 0
	for i := 0; i < nVols; i++ {
		var id string
		var err error
		id = <-idchan
		if id != "" {
			f.volIDs = append(f.volIDs, id)
		}
		err = <-errchan
		if err != nil {
			fmt.Printf("create volume received error: %s\n", err.Error())
			f.errs = append(f.errs, err)
			nerrors++
		}
	}
	t1 := time.Now()
	if len(f.volIDs) > nVols {
		f.volIDs = f.volIDs[0:nVols]
	}
	f.writeResults("create", nVols, nerrors, t0, t1)

	time.Sleep(SleepTime)
	return nil
}

// whenIDeleteVolumesInParallel creates nVols "delete" requests to driver in goroutines
// NOTE: should be ran last because it closes .csv file
func (f *feature) whenIDeleteVolumesInParallel(nVols int) error {
	nVols = len(f.volIDs)
	done := make(chan bool, nVols)
	errchan := make(chan error, nVols)

	// Send requests
	t0 := time.Now()
	for i := 0; i < nVols; i++ {
		id := f.volIDs[i]
		fmt.Printf("deleting %s\n", id)
		if id == "" {
			continue
		}
		go func(id string, done chan bool, errchan chan error) {
			_, err := f.controllerService.DeleteVolume(context.Background(), &csi.DeleteVolumeRequest{VolumeId: id})
			done <- true
			errchan <- err
		}(f.volIDs[i], done, errchan)
	}

	// Wait for responses
	nerrors, err := f.waitOnParallelResponses("Delete volume", done, errchan)
	if err != nil {
		return err
	}
	t1 := time.Now()

	f.writeResults("delete", nVols, nerrors, t0, t1)
	time.Sleep(RetrySleepTime)
	_ = f.file.Close()
	return nil
}

// waitOnParallelResponses helper function that waits until both done and error channels received nVols
func (f *feature) waitOnParallelResponses(method string, done chan bool, errchan chan error) (int, error) {
	nerrors := 0
	for i := 0; i < len(f.volIDs); i++ {
		if f.volIDs[i] == "" {
			continue
		}
		finished := <-done
		if !finished {
			return nerrors, fmt.Errorf("premature completion")
		}
		err := <-errchan
		if err != nil {
			fmt.Printf("%s received error: %s\n", method, err.Error())
			f.errs = append(f.errs, err)
			nerrors++
		}
	}
	return nerrors, nil
}

// iPublishVolumesInParallel creates nVols "controller publish" requests to driver in goroutines
// NOTE: PublishContexts of published volumes are stored inside of feature struct, to be used in later functions
func (f *feature) iPublishVolumesInParallel(nVols int) error {
	nvols := len(f.volIDs)
	contexts := make(chan map[string]string, nvols)
	errchan := make(chan error, nvols)

	// Send requests
	t0 := time.Now()
	for i := 0; i < nVols; i++ {
		id := f.volIDs[i]
		if id == "" {
			continue
		}
		go func(id string, contexts chan map[string]string, errchan chan error) {
			var resp *csi.ControllerPublishVolumeResponse
			var err error
			for j := 0; j < MaxRetryCount; j++ {
				resp, err = f.controllerService.ControllerPublishVolume(context.Background(), &csi.ControllerPublishVolumeRequest{
					VolumeId:         id,
					NodeId:           f.nodeID,
					VolumeCapability: f.capability,
					Readonly:         false,
				})
				if err == nil {
					break
				}
				time.Sleep(RetrySleepTime)
			}
			errchan <- err
			var pubCtx map[string]string
			if resp != nil {
				pubCtx = resp.PublishContext
			}
			contexts <- pubCtx
		}(id, contexts, errchan)
	}

	// Wait on complete, collecting ids and errors
	nerrors := 0
	for i := 0; i < nVols; i++ {
		var ctx map[string]string
		var err error
		ctx = <-contexts
		f.publishContexts = append(f.publishContexts, ctx)

		err = <-errchan
		if err != nil {
			fmt.Printf("create volume received error: %s\n", err.Error())
			f.errs = append(f.errs, err)
			nerrors++
		}
	}
	t1 := time.Now()

	f.writeResults("ctrl publish", nVols, nerrors, t0, t1)
	return nil
}

func (f *feature) iUnpublishVolumesInParallel(nVols int) error {
	nvols := len(f.volIDs)
	done := make(chan bool, nvols)
	errchan := make(chan error, nvols)

	// Send request
	t0 := time.Now()
	for i := 0; i < nVols; i++ {
		id := f.volIDs[i]
		if id == "" {
			continue
		}
		go func(id string, done chan bool, errchan chan error) {
			var err error
			for j := 0; j < MaxRetryCount; j++ {
				_, err = f.controllerService.ControllerUnpublishVolume(context.Background(), &csi.ControllerUnpublishVolumeRequest{
					VolumeId: id,
					NodeId:   f.nodeID,
				})

				if err == nil {
					break
				}
				time.Sleep(RetrySleepTime)
			}
			done <- true
			errchan <- err
		}(id, done, errchan)
	}

	// Wait for responses
	nerrors, err := f.waitOnParallelResponses("Controller unpublish", done, errchan)
	if err != nil {
		return err
	}

	t1 := time.Now()

	f.writeResults("ctrl unpublish", nVols, nerrors, t0, t1)
	return nil
}

// iNodeStageVolumesInParallel creates nVols "node stage" requests to driver in goroutines
func (f *feature) iNodeStageVolumesInParallel(nVols int) error {
	nvols := len(f.volIDs)
	done := make(chan bool, nvols)
	errchan := make(chan error, nvols)

	// // make a staging directory for each
	for i := 0; i < nVols; i++ {
		dataDirName := fmt.Sprintf("/tmp/stagedir%d", i)
		fmt.Printf("Creating %s\n", dataDirName)
		var fileMode os.FileMode
		fileMode = 0777
		err := os.Mkdir(dataDirName, fileMode)
		if err != nil && !os.IsExist(err) {
			fmt.Printf("%s: %s\n", dataDirName, err)
		}
	}

	// Send requests
	t0 := time.Now()
	for i := 0; i < nVols; i++ {
		i := i
		id := f.volIDs[i]
		if id == "" {
			continue
		}
		dataDirName := fmt.Sprintf("/tmp/stagedir%d", i)
		go func(id string, dataDirName string, done chan bool, errchan chan error) {
			var err error
			for j := 0; j < MaxRetryCount; j++ {
				_, err = f.nodeService.NodeStageVolume(context.Background(), &csi.NodeStageVolumeRequest{
					VolumeId:          id,
					PublishContext:    f.publishContexts[i],
					StagingTargetPath: dataDirName,
					VolumeCapability:  f.capability,
				})
				if err == nil {
					break
				}
				time.Sleep(RetrySleepTime)
			}
			done <- true
			errchan <- err
		}(id, dataDirName, done, errchan)
	}

	// Wait for responses
	nerrors, err := f.waitOnParallelResponses("Node stage", done, errchan)
	if err != nil {
		return err
	}

	t1 := time.Now()

	f.writeResults("node stage", nVols, nerrors, t0, t1)
	time.Sleep(5 * SleepTime)
	return nil
}

// iNodeUnstageVolumesInParallel creates nVols "node unstage" requests to driver in goroutines
func (f *feature) iNodeUnstageVolumesInParallel(nVols int) error {
	nvols := len(f.volIDs)
	done := make(chan bool, nvols)
	errchan := make(chan error, nvols)

	// Send requests
	t0 := time.Now()
	for i := 0; i < nVols; i++ {
		id := f.volIDs[i]
		if id == "" {
			continue
		}
		dataDirName := fmt.Sprintf("/tmp/stagedir%d", i)
		go func(id string, dataDirName string, done chan bool, errchan chan error) {
			var err error
			for j := 0; j < MaxRetryCount; j++ {
				_, err = f.nodeService.NodeUnstageVolume(context.Background(), &csi.NodeUnstageVolumeRequest{
					VolumeId:          id,
					StagingTargetPath: dataDirName,
				})
				if err == nil {
					break
				}
				time.Sleep(RetrySleepTime)
			}
			done <- true
			errchan <- err
		}(id, dataDirName, done, errchan)
	}

	// Wait for responses
	nerrors, err := f.waitOnParallelResponses("Node unstage", done, errchan)
	if err != nil {
		return err
	}

	t1 := time.Now()

	f.writeResults("node unstage", nVols, nerrors, t0, t1)
	time.Sleep(5 * SleepTime)
	return nil
}

// iNodePublishVolumesInParallel creates nVols "node publish" requests to driver in goroutines
func (f *feature) iNodePublishVolumesInParallel(nVols int) error {
	nvols := len(f.volIDs)
	done := make(chan bool, nvols)
	errchan := make(chan error, nvols)

	// Send requests
	t0 := time.Now()
	fmt.Println("WRITING ALL THINGS ON SCREEN")
	for i := 0; i < nVols; i++ {
		fmt.Printf("VOL ID: %v\nPUBLISH CTX: %v\n", f.volIDs[i], f.publishContexts[i])
	}
	for i := 0; i < nVols; i++ {
		i := i // https://golang.org/doc/faq#closures_and_goroutines
		id := f.volIDs[i]
		dataDirName := fmt.Sprintf("/tmp/datadir%d", i)
		stageDirName := fmt.Sprintf("/tmp/stagedir%d", i)
		go func(id string, dataDirName string, done chan bool, errchan chan error) {
			var err error
			for j := 0; j < MaxRetryCount; j++ {
				_, err = f.nodeService.NodePublishVolume(context.Background(), &csi.NodePublishVolumeRequest{
					VolumeId:          id,
					PublishContext:    f.publishContexts[i],
					StagingTargetPath: stageDirName,
					TargetPath:        dataDirName,
					VolumeCapability:  f.capability,
					Readonly:          false,
				})
				if err == nil {
					break
				}
				time.Sleep(RetrySleepTime)
			}
			done <- true
			errchan <- err
		}(id, dataDirName, done, errchan)
	}

	// Wait for responses
	nerrors, err := f.waitOnParallelResponses("Node publish", done, errchan)
	if err != nil {
		return err
	}

	t1 := time.Now()

	f.writeResults("node publish", nVols, nerrors, t0, t1)
	time.Sleep(5 * SleepTime)
	return nil
}

// iNodeUnpublishVolumesInParallel creates nVols "node unpublish" requests to driver in goroutines
func (f *feature) iNodeUnpublishVolumesInParallel(nVols int) error {
	nvols := len(f.volIDs)
	done := make(chan bool, nvols)
	errchan := make(chan error, nvols)

	// Send requests
	t0 := time.Now()
	for i := 0; i < nVols; i++ {
		id := f.volIDs[i]
		if id == "" {
			continue
		}
		dataDirName := fmt.Sprintf("/tmp/datadir%d", i)
		go func(id string, dataDirName string, done chan bool, errchan chan error) {
			var err error
			for j := 0; j < MaxRetryCount; j++ {
				_, err = f.nodeService.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{
					VolumeId:   id,
					TargetPath: dataDirName,
				})
				if err == nil {
					break
				}
				time.Sleep(RetrySleepTime)
			}
			done <- true
			errchan <- err
		}(id, dataDirName, done, errchan)
	}

	// Wait for responses
	nerrors, err := f.waitOnParallelResponses("Node unpublish", done, errchan)
	if err != nil {
		return err
	}

	t1 := time.Now()

	f.writeResults("node unpublish", nVols, nerrors, t0, t1)
	return nil
}

// getMountVolumeRequest returns a usual CreateVolumeRequests for mountable volumes
// FS is XFS, size is 100 MB, AccessMode is Single Node Writer
func (f *feature) getMountVolumeRequest(name string) *csi.CreateVolumeRequest {
	req := new(csi.CreateVolumeRequest)
	params := make(map[string]string)
	req.Parameters = params
	req.Name = name
	capacityRange := new(csi.CapacityRange)
	capacityRange.RequiredBytes = 100 * 1024 * 1024
	req.CapacityRange = capacityRange
	capability := new(csi.VolumeCapability)
	mountVolume := new(csi.VolumeCapability_MountVolume)
	mountVolume.FsType = "xfs"
	mountVolume.MountFlags = make([]string, 0)
	mount := new(csi.VolumeCapability_Mount)
	mount.Mount = mountVolume
	capability.AccessType = mount
	accessMode := new(csi.VolumeCapability_AccessMode)
	accessMode.Mode = csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
	capability.AccessMode = accessMode
	f.capability = capability
	capabilities := make([]*csi.VolumeCapability, 0)
	capabilities = append(capabilities, capability)
	req.VolumeCapabilities = capabilities
	return req
}

func FeatureContext(s *godog.Suite) {
	f := &feature{}
	s.Step(`^a PowerStore service$`, f.aPowerStoreService)
	s.Step(`^I create (\d+) volumes in parallel$`, f.iCreateVolumesInParallel)
	s.Step(`^I publish (\d+) volumes in parallel$`, f.iPublishVolumesInParallel)
	s.Step(`^I node stage (\d+) volumes in parallel$`, f.iNodeStageVolumesInParallel)
	s.Step(`^I node publish (\d+) volumes in parallel$`, f.iNodePublishVolumesInParallel)
	s.Step(`^I node unpublish (\d+) volumes in parallel$`, f.iNodeUnpublishVolumesInParallel)
	s.Step(`^I node unstage (\d+) volumes in parallel$`, f.iNodeUnstageVolumesInParallel)
	s.Step(`^I unpublish (\d+) volumes in parallel$`, f.iUnpublishVolumesInParallel)
	s.Step(`^when I delete (\d+) volumes in parallel$`, f.whenIDeleteVolumesInParallel)
	s.Step(`^there are no errors$`, f.thereAreNoErrors)
}
