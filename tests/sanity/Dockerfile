#
#
# Copyright © 2020-2024 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#      http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#

FROM golang:1.24

RUN git clone https://github.com/kubernetes-csi/csi-test.git && \
    cd csi-test/cmd/csi-sanity && \
    make clean install && \
    cp ./csi-sanity /csi-sanity

FROM frolvlad/alpine-glibc
WORKDIR /app/csi-sanity/
COPY --from=build-env /csi-sanity .
COPY params.yaml /params.yaml

ENTRYPOINT [ "./csi-sanity" ]