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

set -euo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname "$0")" && pwd -P)"
ROOT_DIR="$(cd -P -- "${SCRIPT_DIR}/../../" && pwd -P)"
APISERVER_JAR="${ROOT_DIR}/apiserver/target/dependency-track-apiserver.jar"

if [[ ! -f "${APISERVER_JAR}" ]]; then
  echo "Building apiserver jar..."
  (cd "${ROOT_DIR}" && make build)
fi

CONTAINER_ID="$(docker run -d --rm \
  -e 'POSTGRES_DB=dtrack' \
  -e 'POSTGRES_USER=dtrack' \
  -e 'POSTGRES_PASSWORD=dtrack' \
  -p '5432' postgres:14-alpine)"
trap 'docker stop "${CONTAINER_ID}" >/dev/null' EXIT

CONTAINER_PORT="$(docker port "${CONTAINER_ID}" "5432/tcp" | cut -d ':' -f 2)"

while ! docker exec "${CONTAINER_ID}" pg_isready -U dtrack -d dtrack >/dev/null 2>&1; do
  echo 'Waiting for Postgres readiness...'
  sleep 1
done

java \
  -Ddt.datasource.url="jdbc:postgresql://localhost:${CONTAINER_PORT}/dtrack" \
  -Ddt.datasource.username="dtrack" \
  -Ddt.datasource.password="dtrack" \
  -Ddt.init-tasks.exit-after-completion=true \
  -jar "${APISERVER_JAR}"

docker exec "${CONTAINER_ID}" pg_dump -Udtrack --schema-only --no-owner --no-privileges dtrack \
  | sed -E \
      -e '/^--/d' \
      -e '/^\\/d' \
      -e '/^SET (statement_timeout|lock_timeout|idle_in_transaction_session_timeout|client_encoding|standard_conforming_strings|check_function_bodies|xmloption|client_min_messages|row_security|default_tablespace|default_table_access_method)\b/d' \
      -e "/^SELECT pg_catalog\\.set_config\\('search_path'/d" \
      -e '/^ WITH SCHEMA public/d' \
      -e 's/ WITH SCHEMA public//g' \
      -e 's/public\.//g' \
  | cat -s \
  > "${ROOT_DIR}/schema.sql"
