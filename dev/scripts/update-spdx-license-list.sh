#!/usr/bin/env bash

set -euxo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname "$0")" && pwd -P)"
LICENSE_LIST_DATA_DIR="$(cd -P -- "${SCRIPT_DIR}/../../src/main/resources/license-list-data" && pwd -P)"
TMP_DOWNLOAD_FILE="$(mktemp)"

gh -R spdx/license-list-data release download "v$1" \
  --archive tar.gz --clobber --output "${TMP_DOWNLOAD_FILE}"

rm -rf "${LICENSE_LIST_DATA_DIR}/json"

tar -xvzf "${TMP_DOWNLOAD_FILE}" \
  --strip-components "1" \
  --directory "${LICENSE_LIST_DATA_DIR}" \
  "license-list-data-$1/json"
