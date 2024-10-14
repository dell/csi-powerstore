#!/bin/bash

#  Copyright © 2024 Dell Inc. or its subsidiaries. All Rights Reserved.
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

script_path=$(dirname "${BASH_SOURCE[0]}")

# test report
report_file="$script_path/metro-e2e-report.csv"

# script default options
key_path=""
username=$USER

# test resources
test_resources_path="$script_path/resources"
test_resource_sc="sc.yaml"
test_resource_deployment="deployment.yaml"
pod_name=powerstoretest-0
pvc_name="pvol0"
volume_mount_path="/data0"
volume_prefix="csivol-"
namespace=testpowerstore

# test timeouts
timeout_seconds=120
sleep_interval=2

# color codes
red_text="\033[31m"
green_text="\033[32m"
yellow_text="\033[33m"
reset_text="\033[0m"

# Function to handle SIGINT (Ctrl+C)
exit_script() {
    echo "SIGINT received. Exiting script..."
    exit 0
}

# Register the trap for SIGINT
trap "exit_script" SIGINT

# print a message with a preceding newline
function print() {
    local message=$1
    echo -e "\n[$( date +"%Y-%m-%dT%H:%M:%S.%3N")] $message"
}

function print_fail() {
    local test_name=$1
    local error_msg=$2
    print "${red_text}FAIL: $test_name: $error_msg${reset_text}"
    echo "$test_name,fail,$error_msg" >> $report_file
}

function print_pass() {
    local test_name=$1
    print "${green_text}PASS: $1${reset_text}"
    echo "$test_name,pass" >> $report_file
}

function print_notice() {
    print "${yellow_text}$1${reset_text}"
}

# use the exit code of the last command to report success or failure
function pass_fail() {
    local exit_code=$1
    local test_name=$2

    if [[ "$exit_code" -eq 0 ]]; then
        print_pass "$test_name"
    else 
        print_fail "$test_name" ""
    fi
}

# execute a command on a remote host.
# if -k option was provided, use the ssh key
# otherwise, allow the user to authenticate.
function ssh_exec() {
    local host_ip=$1
    local cmd=$2

    if [ -z "$key_path" ]; then
        ssh $username@$host_ip $cmd
    else
        ssh -i $key_path $username@$host_ip $cmd
    fi
}

function run_test() {
    local test_name="$1"

    echo "Running test: $test_name"
    (
        eval "$command"
        local exit_status=$?
        pass_fail $exit_status "$test_name"
    )
}

# deploy the storage class and test environment.
# the test environment consists of a pod, pvc, stateful set, and service account.
function deploy_test_env() {
    print_notice "-> Creating the metro storage class"
    kubectl apply -f $test_resources_path/$test_resource_sc
    if [ $? -ne 0 ]; then
        print_fail "Create metro storage class" "Failed to create storage class"
        return 1
    fi
    print_pass "Create metro storage class"

    print_notice "-> Creating the test environment"
    kubectl apply -f $test_resources_path/$test_resource_deployment
    if [ $? -ne 0 ]; then
        print_fail "Create test environment" "Failed to create test environment"
        return 1
    fi
    print_pass "Create test environment"
}

# confirm a PV is provisioned and bound for the PVC.
# status will be checked in $sleep_interval intervals for $timeout_seconds
function test_pv_provisioning() {
    print_notice "-> Waiting for PV to be provisioned and PVC to bind..."

    # Check the PVC until a PV is provisioned
    local start_time=$(date +%s)
    while true; do
        # Get the PVC status
        pvc_status=$(kubectl get pvc "$pvc_name" -n "$namespace" -o jsonpath='{.status.phase}')

        # Check if a PV is provisioned
        if [[ "$pvc_status" == "Bound" ]]; then
            print_pass "PV is provisioned for the PVC"
            break
        fi

        # Check if the timeout has been reached
        local current_time=$(date +%s)
        local elapsed_time=$((current_time - start_time))
        if [[ "$elapsed_time" -ge "$timeout_seconds" ]]; then
            echo "Timeout reached. PV is not provisioned for the PVC"
            return 1
        fi

        # Sleep for the specified interval
        sleep "$sleep_interval"
    done

    return 0
}

# 
function test_pod_running() {

    print_notice "-> Waiting for pod $pod_name to be ready..."

    local start_time=$(date +%s)
    while true; do
        # Get the PVC status
        pod_status=$(kubectl get pods -n $namespace $pod_name -o jsonpath='{.status.phase}')

        # Check if a PV is provisioned
        if [[ "$pod_status" == "Running" ]]; then
            print_pass "Pod $pod_name is ready"
            break
        fi

        # Check if the timeout has been reached
        local current_time=$(date +%s)
        local elapsed_time=$((current_time - start_time))
        if [[ "$elapsed_time" -ge "$timeout_seconds" ]]; then
            echo "Timeout waiting for pod $pod_name to be ready"
            return 1
        fi

        # Sleep for the specified interval
        sleep "$sleep_interval"
    done

    return 0
}

# returns an array of device paths on the host_ip for the given volume name
# usage: local -a paths=($(get_device_paths "10.10.10.10" "my-vol-name"))
function get_device_paths() {
    local host_ip=$1
    local volume_name=$2
    local device_path_name_pattern='sd[a-z]*'

    local paths=$(ssh_exec $host_ip lsblk | grep $volume_name -B 1 | grep -E $device_path_name_pattern | awk '{print $1}')
    local -a paths_array=(${paths//$'\n'/ })

    echo "${paths_array[@]}"
}

function test_storage_multipath() {
    print_notice "-> Checking storage paths"

    local host_ip=$(kubectl get pod -n $namespace $pod_name -o jsonpath='{.status.hostIP}')
    local volume_name=$(kubectl get pvc -n $namespace $pvc_name -o jsonpath='{.spec.volumeName}')

    # get the device paths from the mountpoint that contains the PV's name
    local -a mountpoints=($(get_device_paths $host_ip $volume_name))

    # confirm there are at least 4 mount points
    if [[ "${#mountpoints[@]}" -lt 4 ]]; then
        print_fail "Test get device mount paths" "Not enough mount paths found for volume '$volume_name'"
        echo "expected 4, found ${#mountpoints[@]}"
        return 1
    fi
    print_pass "Test get device mount paths"

    echo "Found ${#mountpoints[@]} mount paths for volume '$volume_name'"

    for device_path in "${mountpoints[@]}"; do
        # confirm multipath provides at least 4 paths, 2 for each storage system in the metro configuration
        ssh_exec $host_ip 'multipathd show paths' | grep $device_path > /dev/null
        if [[ $? -ne 0 ]]; then
            print_fail "Test host paths exist in multipath" "Could not find device path '$device_path' in multipath"
            return 1
        fi

        echo "Test host path for $device_path exists"
    done
    print_pass "Host paths exist in multipath"


    # confirm the paths are in an 'active ready' state
    print_notice "-> Waiting for paths to be 'active ready'"
    local start_time=$(date +%s)
    while true; do
        local is_ready=0

        for device_path in "${mountpoints[@]}"; do
            ssh_exec $host_ip 'multipathd show paths' | grep $device_path | grep 'active ready' > /dev/null
            if [[ $? -ne 0 ]]; then
                break
            fi

            # reached end of the list and all are 'active ready'
            if [[ $device_path == "${mountpoints[-1]}" ]]; then
                is_ready=1
            fi
        done
        if [[ "$is_ready" -eq 1 ]]; then
            print_pass "All paths are 'active ready'"
            break
        fi

        # Check if the timeout has been reached
        local current_time=$(date +%s)
        local elapsed_time=$((current_time - start_time))
        if [[ "$elapsed_time" -ge "$timeout_seconds" ]]; then
            echo "Timeout waiting namespace '$namespace' to be deleted"
            return 1
        fi
    done

    return 0
}

# write data to the file system mounted to the pod using
# the first argument as the output file name
function write_to_pod_fs() {
    local filename=$1
    kubectl exec -it -n $namespace pods/$pod_name -- /bin/bash -c "dd if=/dev/urandom bs=1M count=128 oflag=sync > $volume_mount_path/$filename"
}

function test_volume_availability() {
    # get the device paths from the mountpoint that contains the PV's name
    local host_ip=$(kubectl get pod -n $namespace $pod_name -o jsonpath='{.status.hostIP}')
    local volume_name=$(kubectl get pvc -n $namespace $pvc_name -o jsonpath='{.spec.volumeName}')

    print_notice "-> Checking file system is writable"
    write_to_pod_fs "test-sanity.txt"
    if [[ $? -ne 0 ]]; then
        print_fail "Test file system is writable" "Failed to write to volume"
        return 1
    fi
    print_pass "Test file system is writable"

    # determine which pair of paths belong to the same storage array.
    print_notice "-> Getting LUN for device paths"

    local -a device_paths=($(get_device_paths $host_ip $volume_name))
    declare -A LUN_IDS
    # get LUN for each device path
    for path in "${device_paths[@]}"; do
        echo "Getting LUN for $path"
        LUN_IDS[$path]=$(ssh_exec $host_ip 'multipathd show paths' | grep $path | awk '{print $1}' | awk -F: '{print $NF}')
        echo "$path: ${LUN_IDS[$path]}"
    done

    # use LUN to take down one side of the metro replication session
    print_notice "-> Taking down one side of the metro replication session"
    local -a paths_to_take_down=($(ssh_exec $host_ip "lsscsi \":::${LUN_IDS[${device_paths[0]}]}\"" | awk '{print $6}' | grep -E 'sd[a-z]*' | awk -F/ '{print $3}'))
    for path in "${paths_to_take_down[@]}"; do
        echo "Taking down $path"
        local response=$(ssh_exec $host_ip "multipathd fail path $path")
        if [[ "$response" != "ok" ]]; then
            print_fail "Test take down host path" "Could not take down path $path"
            return 1
        fi

        print_notice "-> Waiting for paths to transition to 'failed' state"
        local start_time=$(date +%s)
        while true; do

            ssh_exec $host_ip 'multipathd show paths' | grep $path | grep 'failed faulty' > /dev/null
            if [[ $? -eq 0 ]]; then
                print_pass "Test path $path was taken down"
                break
            fi

            # Check if the timeout has been reached
            local current_time=$(date +%s)
            local elapsed_time=$((current_time - start_time))
            if [[ "$elapsed_time" -ge "$timeout_seconds" ]]; then
                echo "Timeout waiting path '$path' to transition to 'failed' state"
                return 1
            fi

            # Sleep for the specified interval
            sleep "$sleep_interval"
        done
    done

    # confirm the volume mounted in the pod is still writable. do a few writes.
    print_notice "-> Confirming the file system is still writable"
    for i in {1..10}; do
        echo "Writing to volume. Iteration $i"
        write_to_pod_fs "test-sanity-$i.txt"
        if [[ $? -ne 0 ]]; then
            print_fail "Test file system is writable: iteration $i" "Failed to write to volume: iteration $i"
            return 1
        else
            print_pass "Test file system is writable: iteration $i"
        fi

        echo "Sleeping for 5 seconds"
        sleep 5
    done

    # restore the first side.
    print_notice "-> Restoring failed paths"
    for path in "${paths_to_take_down[@]}"; do
        echo "Restoring path '$path'"

        $(ssh_exec $host_ip "multipathd reinstate path $path") > /dev/null
    done

    return 0
}

# PROVISIONING TEST
# Confirm a metro PV is provisioned given a valid metro storage class and pvc.
function test_suite_provisioning() {
    echo "Metro Volume Provisioning Test," >> $report_file

    print_notice "-> Starting Provisioning test"

    deploy_test_env
    test_pv_provisioning
    test_pod_running

    pass_fail $? "Metro Volume Provisioning Test"
}

# HOST PATH TEST
# Confirm the PV is setup on the host kubernetes node with multiple paths
# to both the local and remote storage system.
function test_suite_host_path() {
    echo "Host Path Test," >> $report_file
    print_notice "-> Starting Host Path test"

    # confirm PV for PVC is created and bound and get the PV name.
    # confirm Pod is running.
    test_pv_provisioning
    test_pod_running
    # confirm host machine has multiple multipath devices, and the multipaths are mounted
    # for the corresponding PV.
    test_storage_multipath

    pass_fail $? "Host Path Test"
}

# VOLUME AVAILABILITY TEST
# Confirm the volume is still writable after taking down all paths to one
# side of the metro replication session.
function test_suite_volume_availability() {
    echo "Volume Availability Test," >> $report_file
    print_notice "-> Starting Volume Availability test"

    # confirm the volume mounted in the pod is writable.
    test_pv_provisioning
    test_volume_availability

    pass_fail $? "Volume Availability Test"
}

# CLEANUP
function clean_test_env() {
    echo "Cleanup," >> $report_file

    pv_name=$(kubectl get pvc $pvc_name -n $namespace -o jsonpath='{.spec.volumeName}')

    print_notice "-> Deleting artifacts in namespace $namespace"
    kubectl delete ns $namespace --wait=false
    
    print_notice "-> Waiting for namespace '$namespace' to be deleted"
    local start_time=$(date +%s)
    while true; do
        kubectl get ns $namespace > /dev/null
        if [[ $? != 0 ]]; then
            print_pass "namespace '$namespace' successfully deleted"
            break
        fi

        # Check if the timeout has been reached
        local current_time=$(date +%s)
        local elapsed_time=$((current_time - start_time))
        if [[ "$elapsed_time" -ge "$timeout_seconds" ]]; then
            echo "Timeout waiting namespace '$namespace' to be deleted"
            return 1
        fi
    done

    print_notice "-> Waiting for PV '$pv_name' to be deleted"
    start_time=$(date +%s)
    while true; do
        kubectl get pv $pv_name > /dev/null
        if [[ $? != 0 ]]; then
            print_pass "PV '$pv_name' successfully deleted"
            break
        fi

        # Check if the timeout has been reached
        local current_time=$(date +%s)
        local elapsed_time=$((current_time - start_time))
        if [[ "$elapsed_time" -ge "$timeout_seconds" ]]; then
            echo "Timeout waiting PV '$pv_name' to be deleted"
            return 1
        fi
    done

    pass_fail "$?" "Cleanup"
}

function print_usage() {
    # echo "Usage: $0 [OPTIONS]"
    echo -e "\t -u\tusername used to access kubernetes cluster worker nodes."
    echo -e "\t\tDefaults to \$USER: $USER"
    echo -e "\t -k\tPath to ssh key used to access kubernetes cluster worker nodes."
    echo -e "\t\tTypically set to ~/.ssh/id_rsa"
}

function parse_args() {
    # Parse command line arguments
    while getopts ":u:k:" opt; do
        case $opt in
            u)
                username=$OPTARG
                ;;
            k)
                key_path=$OPTARG
                echo "got ssh key"
                ;;
            \?)
                print_usage
                exit 1
                ;;
        esac
    done
    shift $((OPTIND-1))

}

### Main ###
parse_args "$@"

if [[ -f "$report_file" ]]; then
    rm $report_file
else
    touch $report_file
    echo -e "createing report file $report_file"
fi

test_suite_provisioning
test_suite_host_path
test_suite_volume_availability

clean_test_env