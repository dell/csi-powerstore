/*
 *
 * Copyright © 2021-2023 Dell Inc. or its subsidiaries. All Rights Reserved.
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

// Package fs provides wrappers for os/fs dependent operations.
package fs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dell/gofsutil"
	log "github.com/sirupsen/logrus"
)

// A FileInfo describes a file and is returned by Stat and Lstat.
type FileInfo interface {
	Name() string       // base name of the file
	Size() int64        // length in bytes for regular files; system-dependent for others
	Mode() os.FileMode  // file mode bits
	ModTime() time.Time // modification time
	IsDir() bool        // abbreviation for Mode().IsDir()
	Sys() interface{}   // underlying data source (can return nil)
}

// Interface wraps usual os and fs related calls so they can be mocked.
// Also Interface provides access to the gofsutil wrapper UtilInterface with GetUtil() method.
type Interface interface {
	OpenFile(name string, flag int, perm os.FileMode) (*os.File, error)
	Stat(name string) (FileInfo, error)
	Create(name string) (*os.File, error)
	ReadFile(name string) ([]byte, error)
	WriteFile(filename string, data []byte, perm os.FileMode) error
	IsNotExist(err error) bool
	IsDeviceOrResourceBusy(err error) bool
	Mkdir(name string, perm os.FileMode) error
	MkdirAll(name string, perm os.FileMode) error
	Chmod(name string, perm os.FileMode) error
	Remove(name string) error
	RemoveAll(name string) error
	WriteString(file *os.File, str string) (int, error)
	ExecCommand(name string, args ...string) ([]byte, error)
	ExecCommandOutput(name string, args ...string) ([]byte, error)

	GetUtil() UtilInterface

	// wrapper
	ParseProcMounts(ctx context.Context, content io.Reader) ([]gofsutil.Info, error)
	MkFileIdempotent(path string) (bool, error)
	// Network
	NetDial(endpoint string) (net.Conn, error)
}

// UtilInterface is a wrapper of gofsutil.fs functions so they can be mocked
type UtilInterface interface {
	GetDiskFormat(ctx context.Context, disk string) (string, error)
	Format(ctx context.Context, source, target, fsType string, options ...string) error
	FormatAndMount(ctx context.Context, source, target, fsType string, options ...string) error
	Mount(ctx context.Context, source, target, fsType string, options ...string) error
	BindMount(ctx context.Context, source, target string, options ...string) error
	Unmount(ctx context.Context, target string) error
	GetMounts(ctx context.Context) ([]gofsutil.Info, error)
	GetDevMounts(ctx context.Context, dev string) ([]gofsutil.Info, error)
	ValidateDevice(ctx context.Context, source string) (string, error)
	WWNToDevicePath(ctx context.Context, wwn string) (string, string, error)
	RescanSCSIHost(ctx context.Context, targets []string, lun string) error
	RemoveBlockDevice(ctx context.Context, blockDevicePath string) error
	TargetIPLUNToDevicePath(ctx context.Context, targetIP string, lunID int) (map[string]string, error)
	MultipathCommand(ctx context.Context, timeout time.Duration, chroot string, arguments ...string) ([]byte, error)
	GetFCHostPortWWNs(ctx context.Context) ([]string, error)
	IssueLIPToAllFCHosts(ctx context.Context) error
	GetSysBlockDevicesForVolumeWWN(ctx context.Context, volumeWWN string) ([]string, error)
	DeviceRescan(ctx context.Context, devicePath string) error
	ResizeFS(ctx context.Context, volumePath, devicePath, ppathDevice, mpathDevice, fsType string) error
	GetMountInfoFromDevice(ctx context.Context, devID string) (*gofsutil.DeviceMountInfo, error)
	ResizeMultipath(ctx context.Context, deviceName string) error
	FindFSType(ctx context.Context, mountpoint string) (fsType string, err error)
	GetMpathNameFromDevice(ctx context.Context, device string) (string, error)
	GetNVMeController(device string) (string, error)
}

// Fs implementation of FsInterface that uses default os/file calls
type Fs struct {
	Util *gofsutil.FS
}

// GetUtil returns gofsutil.fs wrapper -- UtilInterface.
func (fs *Fs) GetUtil() UtilInterface {
	return fs.Util // #nosec G304
}

// OpenFile is a wrapper of os.OpenFile
func (fs *Fs) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm) // #nosec G304
}

// WriteString is a wrapper of file.WriteString
func (fs *Fs) WriteString(file *os.File, str string) (int, error) {
	return file.WriteString(str) // #nosec G304
}

// Create is a wrapper of os.Create
func (fs *Fs) Create(name string) (*os.File, error) {
	return os.Create(name) // #nosec G304
}

// Chmod is a wrapper of os.Chmod
func (fs *Fs) Chmod(name string, perm os.FileMode) error {
	return os.Chmod(name, perm)
}

// ReadFile is a wrapper of os.ReadFile
func (fs *Fs) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Clean(name))
}

// WriteFile is a wrapper of os.WriteFile
func (fs *Fs) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return os.WriteFile(filepath.Clean(filename), data, perm)
}

// Stat is a wrapper of os.Stat
func (fs *Fs) Stat(name string) (FileInfo, error) {
	return os.Stat(name)
}

// IsNotExist is a wrapper of os.IsNotExist
func (fs *Fs) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

// IsDeviceOrResourceBusy checks for device or resource busy error
func (fs *Fs) IsDeviceOrResourceBusy(err error) bool {
	return errors.Unwrap(err) == syscall.EBUSY
}

// Mkdir is a wrapper of os.Mkdir
func (fs *Fs) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(name, perm)
}

// MkdirAll is a wrapper of os.MkdirAll
func (fs *Fs) MkdirAll(name string, perm os.FileMode) error {
	return os.MkdirAll(name, perm)
}

// Remove is a wrapper of os.Remove
func (fs *Fs) Remove(name string) error {
	return os.Remove(name)
}

// RemoveAll is a wrapper of os.RemoveAll
func (fs *Fs) RemoveAll(name string) error {
	return os.RemoveAll(name)
}

// ExecCommand is a wrapper of exec.Command that returns CombinedOutput
func (fs *Fs) ExecCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput() // #nosec G204
}

// ExecCommandOutput is a wrapper of exec.Command that returns default Output
func (fs *Fs) ExecCommandOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output() // #nosec G204
}

// ParseProcMounts is wrapper of gofsutil.ReadProcMountsFrom global function
func (fs *Fs) ParseProcMounts(
	ctx context.Context,
	content io.Reader,
) ([]gofsutil.Info, error) {
	r, _, err := gofsutil.ReadProcMountsFrom(ctx, content, false,
		gofsutil.ProcMountsFields, gofsutil.DefaultEntryScanFunc())
	return r, err
}

// NetDial is a wrapper for net.Dial func. Uses UDP and 80 port.
func (fs *Fs) NetDial(endpoint string) (net.Conn, error) {
	return net.Dial("udp", fmt.Sprintf("%s:80", endpoint))
}

// MkFileIdempotent creates file if there is none
func (fs *Fs) MkFileIdempotent(path string) (bool, error) {
	st, err := fs.Stat(path)
	if fs.IsNotExist(err) {
		file, err := fs.OpenFile(path, os.O_CREATE, 0o600)
		if err != nil {
			log.WithField("path", path).WithError(err).Error("Unable to create file")
			return false, err
		}
		if err = file.Close(); err != nil {
			return false, fmt.Errorf("could not close file")
		}
		log.WithField("path", path).Debug("created file")
		return true, nil
	}
	if st.IsDir() {
		return false, fmt.Errorf("existing path is a directory")
	}
	return false, nil
}
