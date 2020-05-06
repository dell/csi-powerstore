#!/usr/bin/env bash
DEFAULT_NS="csi-powerstore"
NS=${DEFAULT_NS}

function usage() {
    echo "Help for $PROG"
    echo
    echo "Usage: $PROG options..."
    echo "Options:"
    echo "  --namespace[=]<namespace>  kubernetes namespace to upgrade the CSI driver, default: ${DEFAULT_NS}"
    echo "  -h                         help"
    echo

    exit 0
}

while getopts ":h-:" optchar; do
    case "${optchar}" in
        -) case "${OPTARG}" in
            namespace)
                NS="${!OPTIND}";
                if [[ -z ${NS} ]]; then
                    NS=${DEFAULT_NS};
                else
                    OPTIND=$(( $OPTIND + 1 ));
                fi
                ;;
            namespace=*)
                NS=${OPTARG#*=};
                if [[ -z ${NS} ]]; then NS=${DEFAULT_NS}; fi
                ;;
            *) echo "Unknown option --${OPTARG}";
               echo "For help, run $PROG -h";
               exit 1
                ;;
           esac
            ;;
        h) usage;
            ;;
        *) echo "Unknown option -${OPTARG}";
           echo "For help, run $PROG -h";
           exit 1
            ;;
    esac
done

kubectl --help >&/dev/null || {
	 echo "kubectl required for installation... exiting"; exit 2 
}

# Determine the kubernetes version
kubeversion=$(kubectl version  | grep 'Server Version' | sed -e 's/^.*Minor:"//' -e 's/[+"],.*//')
echo Kubernetes minor version ${kubeversion}

helm_command="helm upgrade --values myvalues.yaml --values csi-powerstore/k8s${kubeversion}-sidecar-images.yaml --namespace $NS csi-powerstore ./csi-powerstore --wait --timeout 180s"
echo "Helm upgrade command:"
echo "  ${helm_command}"
${helm_command}

kubectl get pods --namespace "$NS"
echo "StorageClasses:"
kubectl get storageclass
