package node

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/dell/gopowerstore"
	gopowerstoremock "github.com/dell/gopowerstore/mocks"
	"github.com/stretchr/testify/mock"
)

func TestPosixMode_Success(t *testing.T) {
	isPosixMode := posixMode("0755")
	expected := true
	if isPosixMode != expected {
		t.Errorf(fmt.Sprintf("expected: %v, actual: %v", expected, isPosixMode))
	}
}

func TestPosixMode_Fail(t *testing.T) {
	isPosixMode := posixMode("abcd")
	expected := false
	if isPosixMode != expected {
		t.Errorf(fmt.Sprintf("expected: %v, actual: %v", expected, isPosixMode))
	}
}

func TestNfsv4Acl_Success(t *testing.T) {
	isNfsv4ACLs := nfsv4ACLs("A::OWNER@:RWX")
	expected := true
	if isNfsv4ACLs != expected {
		t.Errorf(fmt.Sprintf("expected: %v, actual: %v", expected, isNfsv4ACLs))
	}
}

func TestNfsv4Acl_Fail(t *testing.T) {
	isNfsv4ACLs := nfsv4ACLs("abcd")
	expected := false
	if isNfsv4ACLs != expected {
		t.Errorf(fmt.Sprintf("expected: %v, actual: %v", expected, isNfsv4ACLs))
	}
}

func TestNfsv4NasServer_Success(t *testing.T) {
	clientMock = new(gopowerstoremock.Client)

	nfsServers := []gopowerstore.NFSServerInstance{
		{
			Id:             validNfsServerID,
			IsNFSv4Enabled: true,
		},
	}

	clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID, NfsServers: nfsServers}, nil)
	clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{Id: validNfsServerID, IsNFSv4Enabled: true}, nil)

	isNFSv4Enabled := nfsv4NasServer(context.Background(), clientMock, validNasName)
	expected := true
	if isNFSv4Enabled != expected {
		t.Errorf(fmt.Sprintf("expected: %v, actual: %v", expected, isNFSv4Enabled))
	}
}

func TestNfsv4NasServer_Err_GetNASByName(t *testing.T) {
	clientMock = new(gopowerstoremock.Client)

	clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID}, errors.New("GetNASByName_fail"))
	clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{Id: validNfsServerID, IsNFSv4Enabled: true}, nil)

	isNFSv4Enabled := nfsv4NasServer(context.Background(), clientMock, validNasName)
	expected := false
	if isNFSv4Enabled != expected {
		t.Errorf(fmt.Sprintf("expected: %v, actual: %v", expected, isNFSv4Enabled))
	}
}

func TestNfsv4NasServer_Err_GetNfsServer(t *testing.T) {
	clientMock = new(gopowerstoremock.Client)

	nfsServers := []gopowerstore.NFSServerInstance{
		{
			Id:             validNfsServerID,
			IsNFSv4Enabled: true,
		},
	}

	clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID, NfsServers: nfsServers}, nil)
	clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{Id: validNfsServerID, IsNFSv4Enabled: true}, errors.New("GetNfsServer_fail"))

	isNFSv4Enabled := nfsv4NasServer(context.Background(), clientMock, validNasName)
	expected := false
	if isNFSv4Enabled != expected {
		t.Errorf(fmt.Sprintf("expected: %v, actual: %v", expected, isNFSv4Enabled))
	}
}

func TestNfsv4NasServer_Fail(t *testing.T) {
	clientMock = new(gopowerstoremock.Client)

	nfsServers := []gopowerstore.NFSServerInstance{
		{
			Id:             validNfsServerID,
			IsNFSv4Enabled: true,
		},
	}

	clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID, NfsServers: nfsServers}, nil)
	clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{Id: validNfsServerID, IsNFSv4Enabled: false}, nil)

	isNFSv4Enabled := nfsv4NasServer(context.Background(), clientMock, validNasName)
	expected := false
	if isNFSv4Enabled != expected {
		t.Errorf(fmt.Sprintf("expected: %v, actual: %v", expected, isNFSv4Enabled))
	}
}

func TestValidateAndSetNfsACLs_Success_nfsv4Acls(t *testing.T) {
	clientMock = new(gopowerstoremock.Client)

	nfsServers := []gopowerstore.NFSServerInstance{
		{
			Id:             validNfsServerID,
			IsNFSv4Enabled: true,
		},
	}

	clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID, NfsServers: nfsServers}, nil)
	clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{Id: validNfsServerID, IsNFSv4Enabled: true}, nil)

	execCommand = executeCommandMock
	defer execCommandReset()

	aclConfigured, err := validateAndSetACLs(context.Background(), validNasName, clientMock, "A::OWNER@:RWX", "dir1")

	if err != nil || aclConfigured == false {
		t.Errorf(fmt.Sprintf("expected: true, actual: %v err: %s", aclConfigured, err.Error()))
	}
}

func TestValidateAndSetNfsACLs_Fail_InvalidAcls(t *testing.T) {
	clientMock = new(gopowerstoremock.Client)

	nfsServers := []gopowerstore.NFSServerInstance{
		{
			Id:             validNfsServerID,
			IsNFSv4Enabled: true,
		},
	}

	clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID, NfsServers: nfsServers}, nil)
	clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{Id: validNfsServerID, IsNFSv4Enabled: true}, nil)

	execCommand = executeCommandMock
	defer execCommandReset()

	aclConfigured, err := validateAndSetACLs(context.Background(), validNasName, clientMock, "abcd", "dir1")

	if err == nil || aclConfigured != false {
		t.Errorf(fmt.Sprintf("expected: false, actual: %v err: %s", aclConfigured, err.Error()))
	}
}

func TestValidateAndSetNfsACLs_Fail_GetNfsServerFail(t *testing.T) {
	clientMock = new(gopowerstoremock.Client)

	nfsServers := []gopowerstore.NFSServerInstance{
		{
			Id:             validNfsServerID,
			IsNFSv4Enabled: true,
		},
	}

	clientMock.On("GetNASByName", mock.Anything, validNasName).Return(gopowerstore.NAS{ID: validNasID, NfsServers: nfsServers}, nil)
	clientMock.On("GetNfsServer", mock.Anything, mock.Anything).Return(gopowerstore.NFSServerInstance{Id: validNfsServerID, IsNFSv4Enabled: true}, errors.New("GetNfsServer_fail"))

	execCommand = executeCommandMock
	defer execCommandReset()

	aclConfigured, err := validateAndSetACLs(context.Background(), validNasName, clientMock, "u::rwx", "dir1")

	if err == nil || aclConfigured != false {
		t.Errorf(fmt.Sprintf("expected: false, actual: %v err: %s", aclConfigured, err.Error()))
	}
}

func executeCommandMock(command []string) ([]byte, error) {
	return []byte("executed command successfully"), nil
}

func execCommandReset() {
	execCommand = executeCommand
}
