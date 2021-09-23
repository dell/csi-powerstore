package controller_test

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	csiext "github.com/dell/dell-csi-extensions/replication"
	"github.com/dell/gopowerstore"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("Replication", func() {
	BeforeEach(func() {
		setVariables()
	})

	Describe("calling GetStorageProtectionGroupStatus()", func() {
		When("getting storage protection group status and state is ok", func() {
			It("should return synchronized status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_OK}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNCHRONIZED,
				))
			})
		})

		When("getting storage protection group status and state is failed over", func() {
			It("should return failed over status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_FAILED_OVER}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_FAILEDOVER,
				))
			})
		})

		When("getting storage protection group status and state is paused (for several reasons)", func() {
			It("should return suspended status (if paused)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_PAUSED}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
			It("should return suspended status (if paused for migration)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_PAUSED_FOR_MIGRATION}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
			It("should return suspended status (if paused for NDU)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_PAUSED_FOR_NDU}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
			It("should return suspended status (if system paused)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_SYSTEM_PAUSED}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SUSPENDED,
				))
			})
		})

		When("getting storage protection group status and state is updating (in progress)", func() {
			It("should return 'sync in progress' status (if failing over)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_FAILING_OVER}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if failing over for DR)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_FAILING_OVER_FOR_DR}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if resuming)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_RESUMING}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if reprotecting)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_REPROTECTING}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if cutover for migration)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_PARTIAL_CUTOVER_FOR_MIGRATION}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if synchronizing)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_SYNCHRONIZING}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
			It("should return 'sync in progress' status (if initializing)", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_INITIALIZING}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_SYNC_IN_PROGRESS,
				))
			})
		})

		When("getting storage protection group status and state is error", func() {
			It("should return invalid status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{State: gopowerstore.RS_STATE_ERROR}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_INVALID,
				))
			})
		})

		When("getting storage protection group status and state does not match with known protection group states", func() {
			It("should return unknown status", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, nil)

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(err).To(BeNil())
				Expect(res.Status.State).To(Equal(
					csiext.StorageProtectionGroupStatus_UNKNOWN,
				))
			})
		})

		When("GlobalID is missing", func() {
			It("should fail", func() {

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(
					ContainSubstring("missing globalID in protection group attributes"),
				)
			})
		})

		When("Array with specified globalID couldn't be found", func() {
			It("should fail", func() {

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "SOMETHING WRONG"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(
					ContainSubstring("can't find array with global id"),
				)
			})
		})

		When("Invalid client response", func() {
			It("should fail", func() {
				clientMock.On("GetReplicationSessionByLocalResourceID", mock.Anything, mock.Anything).Return(
					gopowerstore.ReplicationSession{}, status.Errorf(codes.InvalidArgument, "Invalid client response"))

				req := new(csiext.GetStorageProtectionGroupStatusRequest)
				params := make(map[string]string)
				params["globalID"] = "globalvolid1"
				req.ProtectionGroupAttributes = params
				res, err := ctrlSvc.GetStorageProtectionGroupStatus(context.Background(), req)

				Expect(res).To(BeNil())
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(
					ContainSubstring("Invalid client response"),
				)
			})
		})
	})
})
