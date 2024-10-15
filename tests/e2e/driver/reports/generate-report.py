
# Copyright © 2024 Dell Inc. or its subsidiaries. All Rights Reserved.
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

import csv
import xml.etree.ElementTree as ET
import sys

def csv_to_junit_xml(csv_file, xml_file):
    # Read the CSV file
    with open(csv_file, 'r') as file:
        csv_reader = csv.reader(file)
        rows = list(csv_reader)

    # Create the root element
    root = ET.Element('testsuites', name="Metro E2E")

    # Create the testsuite element
    testsuite = None

    # Create the testcase elements
    for row in rows[0:]:
        # test suites have no pass/fail element
        if len(row[1]) == 0:
            testsuite = ET.SubElement(root, 'testsuite', name=row[0])
            continue

        testcase = ET.SubElement(testsuite, 'testcase', name=row[0])

        # Create the failure element if the result is 'fail'
        if row[1] == 'fail':
            failure = ET.SubElement(testcase, 'failure', message=row[2])

    # Write the XML file
    tree = ET.ElementTree(root)
    tree.write(xml_file, encoding='utf-8', xml_declaration=True)

# Usage example

csv_file = sys.argv[1]
xml_file = 'metro-e2e-report.xml'
csv_to_junit_xml(csv_file, xml_file)
