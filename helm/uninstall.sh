#!/usr/bin/env bash
PROG=`basename $0`
DEFAULT_NS="csi-powerstore"
NS=${DEFAULT_NS}

function usage() {
    echo "Help for $PROG"
    echo
    echo "Usage: $PROG options..."
    echo "Options:"
    echo "  --namespace[=]<namespace>  kubernetes namespace to delete the CSI driver from, default: ${DEFAULT_NS}"
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

kubeversion=$(kubectl version  | grep 'Server Version' | sed -e 's/^.*Minor:"//' -e 's/[+"],.*//')
echo Kubernetes minor version "${kubeversion}"

echo "DELETING DRIVER"
helm delete csi-powerstore -n $NS

kubectl delete ns $NS
