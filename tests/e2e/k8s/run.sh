
#
#
# Copyright © 2022 Dell Inc. or its subsidiaries. All Rights Reserved.
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

# supress ginkgo 2.0 upgrade hints
export ACK_GINKGO_DEPRECATIONS=1.16.5

# ./run.sh "Multiple NAS Test"
# ./run.sh "External Access Test"
# Default to running all tests if no arguments are provided
TEST_FOCUS=""

# Check if a specific test focus is passed as an argument
if [[ ! -z "$1" ]]; then
    TEST_FOCUS="-ginkgo.focus=\"$1\""
fi

# Run the tests
echo "Running tests with focus: $TEST_FOCUS"
eval "go test -timeout=100m -v ./ -ginkgo.v=1 $TEST_FOCUS"

