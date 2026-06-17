#!/usr/bin/env bash

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

set -euxo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname "$0")" && pwd -P)"
LICENSE_LIST_DATA_DIR="$(cd -P -- "${SCRIPT_DIR}/../../apiserver/src/main/resources/license-list-data" && pwd -P)"
TMP_DOWNLOAD_FILE="$(mktemp)"

gh -R spdx/license-list-data release download "v$1" \
  --archive tar.gz --clobber --output "${TMP_DOWNLOAD_FILE}"

rm -rf "${LICENSE_LIST_DATA_DIR}/json"

tar -xvzf "${TMP_DOWNLOAD_FILE}" \
  --strip-components "1" \
  --directory "${LICENSE_LIST_DATA_DIR}" \
  "license-list-data-$1/json"