#!/usr/bin/env bash

sed -E 's/\$\{DS_PROMETHEUS\}/Prometheus/' ./docs/files/grafana-dashboard.json > ./dev/monitoring/grafana/dashboards/apiserver.json
