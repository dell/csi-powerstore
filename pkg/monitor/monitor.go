package monitor

import (
	"context"
	"strings"
	"time"

	"github.com/dell/csi-powerstore/v2/pkg/array"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers"
	"github.com/dell/csi-powerstore/v2/pkg/identifiers/k8sutils"
	log "github.com/sirupsen/logrus"

	csictx "github.com/dell/gocsi/context"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	typedv1core "k8s.io/client-go/kubernetes/typed/core/v1"

	"k8s.io/client-go/tools/record"
)

type Service struct {
	MonitoringInterval time.Duration
	EventRecorder      record.EventRecorderLogger

	array.Locker
}

func NewService(interval time.Duration) *Service {
	if kubeConfigPath, ok := csictx.LookupEnv(context.Background(), identifiers.EnvKubeConfigPath); ok {
		log.Infoln("[Fernando] kubeConfigPath: " + kubeConfigPath)
	} else {
		log.Infoln("[Fernando] kubeConfigPath is not set - using the default kubeconfig")
	}

	return &Service{
		MonitoringInterval: interval,
		EventRecorder:      newEventRecorder(),
	}
}

func newEventRecorder() record.EventRecorderLogger {
	eventBroadcaster := record.NewBroadcaster()

	// To initialize the clientSet field
	k8sutils.CreateKubeClientSet("")

	eventBroadcaster.StartRecordingToSink(&typedv1core.EventSinkImpl{Interface: k8sutils.Clientset.CoreV1().Events("")})

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	return eventBroadcaster.NewRecorder(scheme, corev1.EventSource{})
}

func (s *Service) Monitor(ctx context.Context) error {
	go func() {
		ticker := time.NewTicker(s.MonitoringInterval).C
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker:
				s.monitorArray()
			}
		}
	}()

	return nil
}

func (s *Service) monitorArray() {
	log.Infoln("[Fernando] Perform PowerStore array monitoring...")
	arr := s.DefaultArray()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	volumes := s.CreateVolumeMap(ctx)

	alerts, err := arr.GetClient().GetAlerts(ctx)
	if err != nil {
		log.Errorln(err)
		return
	}

	resourceType := "volume"

	for _, alert := range alerts {
		if alert.ResourceType == resourceType && strings.Contains(alert.Description, "metro") {
			log.Infof("Alert: [%s] - %s", alert.ResourceName, alert.Description)

			if volume, ok := volumes[alert.ResourceName]; ok {
				log.Infof("Volume: %s", volume.Name)

				s.EventRecorder.Event(&volume, corev1.EventTypeWarning, "Alert", alert.Description)
			}
		}
	}
}

func (s *Service) CreateVolumeMap(ctx context.Context) map[string]corev1.PersistentVolume {
	volumes, err := k8sutils.ListVolumes(ctx, "")
	if err != nil {
		log.Errorln(err)
		return nil
	}

	// Create map to easily navigate through volumes.
	volumesMap := make(map[string]corev1.PersistentVolume)
	for _, volume := range volumes.Items {
		volumesMap[volume.Name] = volume
	}

	return volumesMap
}
