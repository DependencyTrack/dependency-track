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

ARG COMMIT_SHA=unknown
ARG APP_VERSION=0.0.0
ARG APP_DIR=/opt/owasp/dependency-track/

FROM eclipse-temurin:25.0.3_9-jre-alpine@sha256:c707c0d18cb9e8556380719f80d96a7529d0746fbb42143893949b98ed2f8943

ARG COMMIT_SHA
ARG APP_VERSION
ARG APP_DIR

ENV TZ=Etc/UTC \
    JAVA_OPTIONS="" \
    LANG=C.UTF-8

WORKDIR ${APP_DIR}
USER nobody

COPY --chown=nobody:0 ./target/v4-migrator.jar ./

ENTRYPOINT ["/bin/sh", "-c", "exec java ${JAVA_OPTIONS} -jar v4-migrator.jar \"$@\"", "--"]
CMD []

LABEL \
    org.opencontainers.image.vendor="OWASP" \
    org.opencontainers.image.title="Dependency-Track v4 Migrator" \
    org.opencontainers.image.description="CLI tool to migrate Dependency-Track v4 data to v5" \
    org.opencontainers.image.version="${APP_VERSION}" \
    org.opencontainers.image.url="https://dependencytrack.org/" \
    org.opencontainers.image.source="https://github.com/DependencyTrack/hyades-apiserver" \
    org.opencontainers.image.revision="${COMMIT_SHA}" \
    org.opencontainers.image.licenses="Apache-2.0"
