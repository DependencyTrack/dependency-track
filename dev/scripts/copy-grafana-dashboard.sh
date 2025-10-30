#!/usr/bin/env bash

set -euxo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname "$0")" && pwd -P)"
ROOT_DIR="$(cd -P -- "${SCRIPT_DIR}/../../" && pwd -P)"

sed -E 's/\$\{DS_PROMETHEUS\}/Prometheus/' \
  "${ROOT_DIR}/docs/files/grafana-dashboard.json" \
  > "${ROOT_DIR}/dev/monitoring/grafana/dashboards/apiserver.json"
