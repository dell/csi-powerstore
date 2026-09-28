#!/bin/bash
#
# Copyright © 2020-2026 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0

# bundle a CSI driver helm chart, installation scripts, and
# container images into a tarball that can be used for offline installations

# display some usage information
usage() {
   echo
   echo "$0"
   echo "Make a package for offline installation of a CSI driver"
   echo
   echo "Arguments:"
   echo "-c             Create an offline bundle"
   echo "-p             Prepare this bundle for installation"
   echo "-r <registry>  Required if preparing offline bundle with '-p'"
   echo "               Supply the registry name/path which will hold the images"
   echo "               For example: my.registry.com:5000/dell/csi"
   echo "-h             Displays this information"
   echo "-v             Pass the helm chart version"
   echo "-n             Use the nightly tag for all CSI images on quay.io/dell"
   echo
   echo "Exactly one of '-c' or '-p' needs to be specified"
   echo
}

# status
# echos a brief status sttement to stdout
status() {
  echo
  echo "*"
  echo "* $@"
  echo
}

# run_command
# runs a shell command
# exits and prints stdout/stderr when a non-zero return code occurs
run_command() {
  CMDOUT=$(eval "${@}" 2>&1)
  local rc=$?

  if [ $rc -ne 0 ]; then
    echo
    echo "ERROR"
    echo "Received a non-zero return code ($rc) from the following comand:"
    echo "  ${@}"
    echo
    echo "Output was:"
    echo "${CMDOUT}"
    echo
    echo "Exiting"
    exit 1
  fi
}

# build_image_manifest
# builds a manifest of all the images referred to by the helm chart
build_image_manifest() {
  local REGEX_COMMENTS="(#.*)"
  local REGEX="([-_./:A-Za-z0-9]{3,}):([-_.A-Za-z0-9]{1,})"

  status "Building image manifest file"
  if [ -e "${IMAGEFILEDIR}" ]; then
    rm -rf "${IMAGEFILEDIR}"
  fi
  if [ -f "${IMAGEMANIFEST}" ]; then
    rm -rf "${IMAGEMANIFEST}"
  fi

  for D in ${DIRS_FOR_IMAGE_NAMES[@]}; do
    echo "   Processing files in ${D}"
    if [ ! -d "${D}" ]; then
      echo "Unable to find directory, ${D}. Skipping"
    else
      # look for strings that appear to be image names, this will
      # - search all files in a diectory looking for strings that make $REGEX
      # - exclude anything with double '//'' as that is a URL and not an image name
      # - make sure at least one '/' is found
      find "${D}" -type f -exec egrep -v "${REGEX_COMMENTS}" {} \; | egrep -oh "${REGEX}"| egrep -v '//' | egrep '/' >> "${IMAGEMANIFEST}.tmp"
    fi
  done

  # Forming this only for drivers supporting standalone helm charts
  if [ ! -z ${DRIVERREPO} ]; then
   echo "${DRIVERREPO}/${DRIVERNAME}\:${DRIVERVERSIONVALUESYAML}"
   echo "${DRIVERREPO}/${DRIVERNAME}:${DRIVERVERSIONVALUESYAML}" >> "${IMAGEMANIFEST}.tmp"
  fi
  # sort and uniqify the list
  cat "${IMAGEMANIFEST}.tmp" | sort | uniq > "${IMAGEMANIFEST}"
  rm "${IMAGEMANIFEST}.tmp"
}

# archive_images
# archive the necessary docker images by pulling them locally and then saving them
archive_images() {
  status "Pulling and saving container images"

  if [ ! -d "${IMAGEFILEDIR}" ]; then
    mkdir -p "${IMAGEFILEDIR}"
  fi

  # the images, pull first in case some are not local
  while read line; do
      echo "   $line"
      if [[ "$NIGHTLY" = "true" ]] && [[ "$line" =~ quay.io/dell/container-storage-modules ]]; then
        dockerImage=$(echo $line | sed 's/:[^:]*$/:nightly/')
        run_command "${DOCKER}" pull "${dockerImage}" && run_command "${DOCKER}" tag "${dockerImage}" "${line}"
      else
        run_command "${DOCKER}" pull "${line}"
      fi

      IMAGEFILE=$(echo "${line}" | sed 's|[/:]|-|g')
      # if we already have the image exported, skip it
      if [ ! -f "${IMAGEFILEDIR}/${IMAGEFILE}.tar" ]; then
        run_command "${DOCKER}" save -o "${IMAGEFILEDIR}/${IMAGEFILE}.tar" "${line}"
      fi
  done < "${IMAGEMANIFEST}"
}

# restore_images
# load the images from an archive into the local registry
# then push them to the target registry
restore_images() {
  status "Loading docker images"
  find "${IMAGEFILEDIR}" -name \*.tar -exec "${DOCKER}" load -i {} \; 2>/dev/null

  status "Tagging and pushing images"
  while read line; do
      local NEWNAME="${REGISTRY}${line##*/}"
      echo "   $line -> ${NEWNAME}"
      run_command "${DOCKER}" tag "${line}" "${NEWNAME}"
      run_command "${DOCKER}" push "${NEWNAME}"
  done < "${IMAGEMANIFEST}"
}

# copy in any necessary files
copy_files() {
  status "Copying necessary files"
  for f in ${REQUIRED_FILES[@]}; do
    echo " ${f}"
    if [[ ${f} == *$DRIVER ]]; then
      mkdir -p ${DISTDIR}/helm-charts/charts
      cp -R "${f}" "${DISTDIR}/helm-charts/charts"
    else
      cp -R "${f}" "${DISTDIR}"
    fi

    if [ $? -ne 0 ]; then
      echo "Unable to copy ${f} to the distribution directory"
      exit 1
    fi
  done
}

# strip_quotes_and_trim
# removes leading/trailing whitespace and optional surrounding quotes from a string
strip_quotes_and_trim() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  v="${v#\"}"
  v="${v%\"}"
  v="${v#\'}"
  v="${v%\'}"
  # re-trim in case quotes enclosed whitespace
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  printf '%s' "$v"
}

# collect_helm_dependencies
# parses Chart.yaml dependencies with local file:// repositories and records
# their source directories so they can be included in the offline bundle.
collect_helm_dependencies() {
  if [ "${MODE}" != "helm" ]; then
    return
  fi
  if [ ! -f "${CHARTFILE}" ]; then
    return
  fi

  local charts_root
  charts_root=$(cd "${HELMDIR}/.." >/dev/null 2>&1 && pwd) || {
    echo "WARNING: unable to determine parent charts directory for ${HELMDIR}"
    return
  }

  HELM_DEPS=()
  while IFS= read -r repo; do
    repo=$(strip_quotes_and_trim "${repo}")
    case "${repo}" in
      file://*)
        local rel_path
        rel_path=$(strip_quotes_and_trim "${repo#file://}")
        local dep_dir
        dep_dir=$(cd "${HELMDIR}" >/dev/null 2>&1 && cd "${rel_path}" >/dev/null 2>&1 && pwd)
        if [ -d "${dep_dir}" ]; then
          case "${dep_dir}" in
            "${charts_root}/"*)
              echo "   Found local Helm chart dependency: $(basename "${dep_dir}")"
              DIRS_FOR_IMAGE_NAMES+=("${dep_dir}")
              HELM_DEPS+=("${dep_dir}")
              ;;
            *)
              echo "WARNING: local chart dependency ${rel_path} resolves outside ${charts_root}; skipping"
              ;;
          esac
        else
          echo "WARNING: local chart dependency ${rel_path} not found at ${dep_dir}; skipping"
        fi
        ;;
    esac
  done < <(awk '/^dependencies:/{in_deps=1;next} /^[A-Za-z]/{if(in_deps) in_deps=0} in_deps && /^[[:space:]]*repository:/ {sub(/^[[:space:]]*repository:[[:space:]]*/, ""); print}' "${CHARTFILE}")
}

# copy_helm_dependencies
# copies the local chart dependencies discovered by collect_helm_dependencies
# into the bundle so helm dependency build works in air-gapped environments.
copy_helm_dependencies() {
  if [ "${#HELM_DEPS[@]}" -eq 0 ]; then
    return
  fi

  status "Copying local Helm chart dependencies"
  mkdir -p "${DISTDIR}/helm-charts/charts"
  for dep_dir in "${HELM_DEPS[@]}"; do
    local dep_name
    dep_name=$(basename "${dep_dir}")
    echo "   ${dep_name}"
    if ! cp -R "${dep_dir}" "${DISTDIR}/helm-charts/charts/"; then
      echo "Unable to copy ${dep_dir} to the distribution directory"
      exit 1
    fi
  done
}

# sed_escape_search
# escapes characters that are special in a sed BRE search pattern
# (^ $ . * [ ] \ and the current sed delimiter |). It deliberately does
# NOT escape ?, +, (, ), {, } because those are not metacharacters in BRE.
sed_escape_search() {
  printf '%s' "$1" | sed -e 's/[][\\^$.\\*|]/\\&/g'
}

# sed_escape_replace
# escapes characters that are special in a sed replacement string
sed_escape_replace() {
  printf '%s' "$1" | sed -e 's/[\\&]/\\&/g' -e 's/|/\\|/g'
}

# fix any references in the helm charts or operator configuration
fixup_files() {

  local ROOTDIR="${HELMDIR}"
  local -a SEARCH_DIRS=("${HELMDIR}")

  if [ "${MODE}" == "operator" ]; then
    ROOTDIR="${REPODIR}"
    SEARCH_DIRS=("${REPODIR}")
  fi

  if [ "${MODE}" == "helm" ]; then
    # Include sibling local chart dependencies (e.g. csm-disaster-recovery)
    # so any images they reference are also retagged for the target registry.
    ROOTDIR=$(dirname "${HELMDIR}")
    SEARCH_DIRS=("${HELMDIR}")
    if [ "${#HELM_DEPS[@]}" -gt 0 ]; then
      SEARCH_DIRS+=("${HELM_DEPS[@]}")
    fi
  fi

  status "Preparing ${MODE} files within ${ROOTDIR}"

  # for each image in the manifest, replace the old name with the new
  while IFS= read -r line; do
    local NEWNAME="${REGISTRY}${line##*/}"
    echo "   changing: $line -> ${NEWNAME}"
    local search_escaped
    local replace_escaped
    search_escaped=$(sed_escape_search "${line}")
    replace_escaped=$(sed_escape_replace "${NEWNAME}")
    if ! find "${SEARCH_DIRS[@]}" -type f -not -path "${SCRIPTDIR}/*" -exec sed -i "s|${search_escaped}|${replace_escaped}|g" {} \; ; then
      echo "ERROR: failed to replace image reference ${line}"
      exit 1
    fi
  done < "${IMAGEMANIFEST}"

  # Replacing values file with local registry
  local reg_escaped
  reg_escaped=$(sed_escape_replace "${REGISTRY}")
  sed -i "s|driverRepository:.*|driverRepository: ${reg_escaped}|" "${VALUESFILE}" || {
    echo "ERROR: failed to update driverRepository in ${VALUESFILE}"
    exit 1
  }
  sed -i 's/\/$//' "${VALUESFILE}" || {
    echo "ERROR: failed to trim trailing slash in ${VALUESFILE}"
    exit 1
  }
}

# compress the whole bundle
compress_bundle() {
  status "Compressing release"
  cd "${DISTBASE}" && tar cvfz "${DISTFILE}" "${DRIVERDIR}"
  if [ $? -ne 0 ]; then
    echo "Unable to package build"
    exit 1
  fi
  rm -rf "${DISTDIR}"
}

# copy_helm_dir
# make a copy of the helm directory if one does not already exist
copy_helm_dir() {
  if [ "${MODE}" != "helm" ]; then
    return
  fi

  status "Ensuring a copy of the helm directory exists"
  if [ -d "${HELMBACKUPDIR}" ]; then
    return
  fi

  mkdir -p "${HELMBACKUPDIR}"
  cp -R "${HELMDIR}/../.."/* "${HELMBACKUPDIR}"
}

# set_mode
# figure out if we are working from:
# - a driver repo and using helm
# - the operator repo which means we are using an operator
set_mode() {
  # default is helm
  MODE="helm"

  if [ ! -d "${HELMDIR}" ]; then
    MODE="operator"
  fi
}

#------------------------------------------------------------------------------
#
# Main script logic starts here
#

# default values, overridable by users
CREATE="false"
PREPARE="false"
REGISTRY=""
NIGHTLY="false"
DRIVER="csi-powerstore"
DEFAULT_VERSION="v2.18.0"

while getopts "cprnv:h" opt; do
  case $opt in

    c)
      CREATE="true"
      ;;
    p)
      PREPARE="true"
      ;;
    r)
      REGISTRY="${!OPTIND}"
      OPTIND=$((OPTIND + 1))
      ;;
    v)
      HELMCHARTVERSION="${OPTARG}"
      ;;
    h)
      usage
      exit 0
      ;;
    n)
      NIGHTLY="true"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Derive DRIVERVERSION from DEFAULT_VERSION (single source of truth)
DRIVERVERSION="${DRIVER}-${DEFAULT_VERSION#v}"

# Allow override via -v option
if [ -n "$HELMCHARTVERSION" ]; then
  DRIVERVERSION=$HELMCHARTVERSION
fi

# some directories
SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPODIR="$( dirname "${SCRIPTDIR}" )"
if [ ! -d "$REPODIR/helm-charts" ]; then

  if  [ ! -d "$SCRIPTDIR/helm-charts" ]; then
    git clone --quiet -c advice.detachedHead=false -b $DRIVERVERSION https://github.com/dell/helm-charts
  fi
  mv helm-charts $REPODIR
else
  if [  -d "$SCRIPTDIR/helm-charts" ]; then
    rm -rf $SCRIPTDIR/helm-charts
  fi
fi

HELMDIR="${REPODIR}/helm-charts/charts/$DRIVER"
HELMBACKUPDIR="${REPODIR}/helm-original"

# mode we are using for install, "helm" or "operator"
set_mode

if [ "${MODE}" == "helm" ]; then
  INSTALLERDIR="${REPODIR}/dell-csi-helm-installer"
  CHARTFILE=$(find "${HELMDIR}" -maxdepth 2 -type f -name Chart.yaml)
  VALUESFILE=$(find "${HELMDIR}" -maxdepth 2 -type f -name values.yaml)

   # some output files
  DRIVERNAME=$(grep -oh "^name:\s.*" "${CHARTFILE}" | awk '{print $2}')
  DRIVERNAME=${DRIVERNAME:-"dell-csi-driver"}
  DRIVERVERSION=$(grep -oh "^version:\s.*" "${CHARTFILE}" | awk '{print $2}' | sed -e 's/^"//' -e 's/"$//')
  DRIVERVERSION=${DRIVERVERSION:-unknown}
  DRIVERVERSIONVALUESYAML=$(grep -oh "^version:\s.*" "${VALUESFILE}" | awk '{print $2}' | sed -e 's/^"//' -e 's/"$//')
  DRIVERREPO=$(grep -oh "driverRepository:\s.*" "${VALUESFILE}" | awk '{print $2}')
  DISTBASE="${REPODIR}"
  DRIVERDIR="${DRIVERNAME}-bundle-${DRIVERVERSION}"
  DISTDIR="${DISTBASE}/${DRIVERDIR}"
  DISTFILE="${DISTBASE}/${DRIVERDIR}.tar.gz"
  IMAGEMANIFEST="${INSTALLERDIR}/images.manifest"
  IMAGEFILEDIR="${INSTALLERDIR}/images.tar"

  # directories to search all files for image names
  DIRS_FOR_IMAGE_NAMES=(
    "${HELMDIR}"
  )
  # list of all files to be included
  REQUIRED_FILES=(
    "${HELMDIR}"
    "${INSTALLERDIR}"
    "${REPODIR}/*.md"
    "${REPODIR}/LICENSE"
  )
else
  DRIVERNAME="dell-csm-operator"
  DISTBASE="${REPODIR}"
  DRIVERDIR="${DRIVERNAME}-bundle"
  DISTDIR="${DISTBASE}/${DRIVERDIR}"
  DISTFILE="${DISTBASE}/${DRIVERDIR}.tar.gz"
  IMAGEMANIFEST="${REPODIR}/scripts/images.manifest"
  IMAGEFILEDIR="${REPODIR}/scripts/images.tar"


  # directories to search all files for image names
  DIRS_FOR_IMAGE_NAMES=(
    "${REPODIR}/driverconfig"
    "${REPODIR}/deploy"
    "${REPODIR}/samples"
  )

  # list of all files to be included
  REQUIRED_FILES=(
    "${REPODIR}/driverconfig"
    "${REPODIR}/deploy"
    "${REPODIR}/samples"
    "${REPODIR}/scripts"
    "${REPODIR}/*.md"
    "${REPODIR}/LICENSE"
  )
fi

# discover any local file:// Helm chart dependencies
collect_helm_dependencies

# make sure exatly one option for create/prepare was specified
if [ "${CREATE}" == "${PREPARE}" ]; then
  usage
  exit 1
fi

# validate prepare arguments
if [ "${PREPARE}" == "true" ]; then
  if [ "${REGISTRY}" == "" ]; then
    usage
    exit 1
  fi
fi

if [ "${REGISTRY: -1}" != "/" ]; then
  REGISTRY="${REGISTRY}/"
fi

# figure out if we should use docker or podman, preferring docker
DOCKER=$(which docker 2>/dev/null || which podman 2>/dev/null)
if [ "${DOCKER}" == "" ]; then
  echo "Unable to find either docker or podman in $PATH"
  exit 1
fi

# create a bundle
if [ "${CREATE}" == "true" ]; then
  if [ -d "${DISTDIR}" ]; then
    rm -rf "${DISTDIR}"
  fi
  if [ ! -d "${DISTDIR}" ]; then
    mkdir -p "${DISTDIR}"
  fi
  if [ -f "${DISTFILE}" ]; then
    rm -f "${DISTFILE}"
  fi
  build_image_manifest
  archive_images
  copy_files
  copy_helm_dependencies
  compress_bundle

  status "Complete"
  echo "Offline bundle file is: ${DISTFILE}"
fi

# prepare a bundle for installation
if [ "${PREPARE}" == "true" ]; then
  echo "Preparing a offline bundle for installation"
  restore_images
  copy_helm_dir
  fixup_files

  status "Complete"

  if [ "${MODE}" == "helm" ]; then
    echo "Installation of the ${DRIVERNAME} driver can now be performed via"
    echo "the scripts in ${INSTALLERDIR}"
  fi
fi

echo

exit 0
