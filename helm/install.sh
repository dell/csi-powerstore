#!/usr/bin/env bash


PROG=`basename $0`
VERIFY=1
DEFAULT_NS="csi-powerstore"
NS=${DEFAULT_NS}


function usage() {
    echo "Help for $PROG"
    echo
    echo "Usage: $PROG options..."
    echo "Options:"
    echo "  --namespace[=]<namespace>  kubernetes namespace to install the CSI driver, default: ${DEFAULT_NS}"
    echo "  --skip_verify              skip the kubernetes configuration verification to use the CSI driver"
    echo "  -h                         help"
    echo

    exit 0
}

function kubectl_safe () {
  eval "kubectl $1"
  exitcode=$?
    if [[ $exitcode != 0 ]]; then
        echo "$2"; exit $exitcode;
    fi
}

function verification_k8s() {
    ./verify.sh
    rc=$?
    if [[ ${rc} -ne 0 ]]; then
        echo "*******************************************************************************"
        echo "Warning: Kubernetes --feature-gates not correctly configured. Please validate that they are configured correctly!"
        echo "*******************************************************************************"
    fi
}

function install_csi_crd() {
    echo "Installing CRDs"
    # Check for required CustomResourceDefinitions
    kubectl get customresourcedefinitions | grep csidrivers --quiet
    if [[ $? -ne 0 ]];
        then echo "installing csidrivers CRD"; kubectl create -f csidriver.yaml
    fi
    kubectl get customresourcedefinitions | grep csinodeinfos --quiet
    if [[ $? -ne 0 ]];
        then echo "installing csinodeinfos CRD"; kubectl create -f csinodeinfos.yaml
    fi
}

while getopts ":h-:" optchar; do
    case "${optchar}" in
        -) case "${OPTARG}" in
            skip_verify)
                VERIFY=0
                ;;
            namespace)
                NS="${!OPTIND}";
                if [[ -z ${NS} || ${NS} == "--skip_verify" ]]; then
                    NS=${DEFAULT_NS};
                else
                    OPTIND=$((OPTIND+1));
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

# Verify the kubernetes installation has the feature gates needed.
if [[ ${VERIFY} -eq 1 ]]; then
    verification_k8s
fi

# Determine the kubernetes version
kubeversion=$(kubectl version  | grep 'Server Version' | sed -e 's/^.*Minor:"//' -e 's/[+"],.*//')
echo Kubernetes minor version "${kubeversion}"


kubectl_safe "create ns $NS" "Failed to create namespace $NS"

helm_command="helm install --values myvalues.yaml --values csi-powerstore/k8s${kubeversion}-sidecar-images.yaml --name-template csi-powerstore --namespace $NS ./csi-powerstore --wait --timeout 180s"
echo "Helm install command:"
echo "  ${helm_command}"
${helm_command}

kubectl get pods --namespace "$NS"
echo "StorageClasses:"
kubectl get storageclass


