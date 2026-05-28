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

# Arguments that can be passed at build time
# Directory names must end with / to avoid errors when COPYing
ARG COMMIT_SHA=unknown
ARG APP_VERSION=0.0.0
ARG APP_DIR=/opt/owasp/dependency-track/
ARG DATA_DIR=/data/
ARG UID=1000
ARG GID=1000

FROM eclipse-temurin:26.0.1_8-jdk-alpine@sha256:67d858361411ee84a1510f560757b188a85349d62895767ea05dcf4fb0a9a285 AS jre-build

WORKDIR /work

COPY --chmod=755 ./src/main/docker/create-jre.sh ./
COPY ./target/lib/ ./lib/
COPY ./target/dependency-track-apiserver.jar ./

RUN ./create-jre.sh -i ./dependency-track-apiserver.jar -o ./jre

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

ARG COMMIT_SHA
ARG APP_VERSION
ARG APP_DIR
ARG DATA_DIR
ARG UID
ARG GID

ENV TZ=Etc/UTC \
    # JVM Options that are passed at runtime by default
    JAVA_OPTIONS="-XX:+UseG1GC -XX:+UseStringDeduplication -XX:+UseCompactObjectHeaders -XX:MaxGCPauseMillis=250 -XX:MaxRAMPercentage=80.0" \
    # JVM Options that can be passed at runtime, while maintaining also those set in JAVA_OPTIONS.
    # e.g. EXTRA_JAVA_OPTIONS="-Dlogback.configurationFile=logback-json.xml"
    EXTRA_JAVA_OPTIONS="" \
    # The web context defaults to the root. To override, supply an alternative context which starts with a / but does not end with one
    # Example: /dtrack
    CONTEXT="/" \
    JAVA_HOME=/opt/java/openjdk \
    PATH="/opt/java/openjdk/bin:${PATH}" \
    LANG=C.UTF-8 \
    # Ensure user home is always set to DATA_DIR, even for arbitrary UIDs (such as used by OpenShift)
    HOME=${DATA_DIR} \
    # Default notification publisher templates override environment variables
    DEFAULT_TEMPLATES_OVERRIDE_ENABLED=false \
    DEFAULT_TEMPLATES_OVERRIDE_BASE_DIRECTORY=${DATA_DIR}

# Create the directories where the JAR will be deployed to (${APP_DIR}) and Dependency-Track will store its data (${DATA_DIR})
# Create a user and assign home directory to a ${DATA_DIR}
# Ensure UID 1000 & GID 1000 own all the needed directories
RUN mkdir -p ${APP_DIR} ${DATA_DIR} \
    && addgroup -S -g ${GID} dtrack \
    && adduser -S -D -G dtrack -H -h ${DATA_DIR} -g "dtrack user" -s /bin/false -u ${UID} dtrack \
    && chown -R dtrack:0 ${DATA_DIR} ${APP_DIR} \
    && chmod -R g=u ${DATA_DIR} ${APP_DIR} \
    && apk add --no-cache curl gcompat tini tzdata

WORKDIR ${APP_DIR}
USER ${UID}

COPY --from=jre-build --chown=${UID}:0 /work/jre ${JAVA_HOME}
COPY --chown=${UID}:0 ./target/lib/ ./lib/
COPY --chown=${UID}:0 ./target/dependency-track-apiserver.jar ./src/main/docker/logback-json.xml ./

ENTRYPOINT ["/sbin/tini", "--"]

# Launch Dependency-Track
CMD [ \
    "/bin/sh", "-c", \
    "exec java \
        ${JAVA_OPTIONS} \
        ${EXTRA_JAVA_OPTIONS} \
        --add-opens java.base/java.util.concurrent=ALL-UNNAMED \
        --enable-native-access=ALL-UNNAMED \
        --sun-misc-unsafe-memory-access=allow \
        -cp 'dependency-track-apiserver.jar:lib/*' \
        org.dependencytrack.Application \
        -context ${CONTEXT}" \
]

# Specify which ports Dependency-Track listens on
EXPOSE 8080
EXPOSE 9000

# Health check against the management port
HEALTHCHECK --interval=30s --start-period=60s --timeout=5s CMD [ \
    "/bin/sh", "-c", \
    "curl -f -s --max-time 3 --noproxy '*' -o /dev/null http://127.0.0.1:9000/health" \
]

# metadata labels
LABEL \
    org.opencontainers.image.vendor="OWASP" \
    org.opencontainers.image.title="Official Dependency-Track Container image" \
    org.opencontainers.image.description="Dependency-Track is an intelligent Component Analysis platform" \
    org.opencontainers.image.version="${APP_VERSION}" \
    org.opencontainers.image.url="https://dependencytrack.org/" \
    org.opencontainers.image.source="https://github.com/DependencyTrack/dependency-track" \
    org.opencontainers.image.revision="${COMMIT_SHA}" \
    org.opencontainers.image.licenses="Apache-2.0" \
    maintainer="steve.springett@owasp.org"
