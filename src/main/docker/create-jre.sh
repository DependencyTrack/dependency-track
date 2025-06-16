#!/bin/sh

# This file is part of Dependency-Track.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

set -eo pipefail

function printHelp() {
  echo "Create a minimal Java Runtime Environment (JRE) using jlink."
  echo ""
  echo "Usage: ${0} [-i <INPUT_JAR_FILE>] [-o <OUTPUT_DIR>]"
  echo "Options:"
  echo " -i   Set the path to the input JAR file"
  echo " -o   Set the path to output the JRE to"
  echo ""
}

while getopts ":h:i:o:" opt; do
  case $opt in
    i)
      input_jar="${OPTARG}"
      ;;
    o)
      output_dir="${OPTARG}"
      ;;
    h)
      printHelp
      exit
      ;;
    *)
      printHelp
      exit
      ;;
  esac
done

if [ -z "${input_jar}" ]; then
  echo '[x] no input JAR provided'
  exit 1
fi

if [ -z "${output_dir}" ]; then
  echo '[x] no output directory provided'
  exit 1
fi

work_dir="$(mktemp -d)"

# Module dependencies that jdeps fails to detect.
#   jdk.crypto.ec: Required for TLS connections that use elliptic curve cryptography.
#   jdk.zipfs:     Required by code that reads files from JAR files at runtime.
static_module_deps='jdk.crypto.ec,jdk.zipfs'

echo "[+] extracting $(basename "${input_jar}") to ${work_dir}"
unzip -qq "${input_jar}" -d "${work_dir}"

echo '[+] detecting module dependencies'
jdeps \
  --class-path "${work_dir}:${work_dir}/WEB-INF/lib/*" \
  --print-module-deps \
  --ignore-missing-deps \
  --multi-release 21 \
  "${work_dir}/WEB-INF/classes" \
  > "${work_dir}/module-deps.txt"

module_deps="$(cat "${work_dir}/module-deps.txt"),${static_module_deps}"
echo "[+] identified module dependencies: ${module_deps}"

echo "[+] creating jre at ${output_dir}"
jlink \
  --compress zip-6 \
  --strip-debug \
  --no-header-files \
  --no-man-pages \
  --add-modules "${module_deps}" \
  --output "${output_dir}"

echo "[+] removing ${work_dir}"
rm -rf "${work_dir}"