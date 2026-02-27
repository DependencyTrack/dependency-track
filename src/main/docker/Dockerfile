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
ARG WAR_FILENAME=dependency-track-apiserver.jar

FROM eclipse-temurin:25.0.2_10-jre-jammy@sha256:2866f12d7d9dc8d33f018d87fa4e0e9befe066d94affe8e22d72357877f907de AS jre-build

FROM debian:stable-slim@sha256:85dfcffff3c1e193877f143d05eaba8ae7f3f95cb0a32e0bc04a448077e1ac69

ARG COMMIT_SHA
ARG APP_VERSION
ARG APP_DIR
ARG DATA_DIR
ARG UID
ARG GID
ARG WAR_FILENAME

ENV TZ=Etc/UTC \
    # Dependency-Track's default logging level
    LOGGING_LEVEL=INFO \
    # JVM Options that are passed at runtime by default
    JAVA_OPTIONS="-XX:+UseG1GC -XX:+UseStringDeduplication -XX:+UseCompactObjectHeaders -XX:MaxRAMPercentage=80.0 -XX:MaxGCPauseMillis=250" \
    # JVM Options that can be passed at runtime, while maintaining also those set in JAVA_OPTIONS
    EXTRA_JAVA_OPTIONS="" \
    # The web context defaults to the root. To override, supply an alternative context which starts with a / but does not end with one
    # Example: /dtrack
    CONTEXT="/" \
    # Injects the build-time ARG "WAR_FILENAME" as an environment variable that can be used in the CMD.
    WAR_FILENAME=${WAR_FILENAME} \
    # Set JAVA_HOME for the copied over JRE
    JAVA_HOME=/opt/java/openjdk \
    PATH="/opt/java/openjdk/bin:${PATH}" \
    LANG=C.UTF-8 \
    # Ensure user home is always set to DATA_DIR, even for arbitrary UIDs (such as used by OpenShift)
    HOME=${DATA_DIR} \
    # Default notification publisher templates override environment variables
    DEFAULT_TEMPLATES_OVERRIDE_ENABLED=false \
    DEFAULT_TEMPLATES_OVERRIDE_BASE_DIRECTORY=${DATA_DIR} \
    LOGGING_CONFIG_PATH="logback.xml"

# Create the directories where the WAR will be deployed to (${APP_DIR}) and Dependency-Track will store its data (${DATA_DIR})
# Create a user and assign home directory to a ${DATA_DIR}
# Ensure UID 1000 & GID 1000 own all the needed directories
RUN mkdir -p ${APP_DIR} ${DATA_DIR} \
    && groupadd --system --gid ${GID} dtrack \
    && useradd --system --no-user-group --gid dtrack --no-create-home --home-dir ${DATA_DIR} --comment "dtrack user" --shell /bin/false --uid ${UID} dtrack \
    && chown -R dtrack:0 ${DATA_DIR} ${APP_DIR} \
    && chmod -R g=u ${DATA_DIR} ${APP_DIR} \
    \
    # Install curl for health check
    && apt-get -yqq update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yqq --no-install-recommends curl tini \
    && rm -rf /var/lib/apt/lists/*

USER ${UID}
WORKDIR ${APP_DIR}

COPY --from=jre-build --chown=${UID}:0 /opt/java/openjdk $JAVA_HOME
COPY --chown=${UID}:0 ./target/${WAR_FILENAME} ./src/main/docker/logback-json.xml ./

ENTRYPOINT ["/usr/bin/tini", "--"]

# Launch Dependency-Track
CMD [ \
    "/bin/sh", "-c", \
    "java_opts=\$(printf '%s' \"\$JAVA_OPTIONS\" | sed \"s/^['\\\"']//;s/['\\\"']\\$//\"); \
    extra_opts=\$(printf '%s' \"\$EXTRA_JAVA_OPTIONS\" | sed \"s/^['\\\"']//;s/['\\\"']\\$//\"); \
    exec java \$java_opts \$extra_opts \
        --add-opens java.base/java.util.concurrent=ALL-UNNAMED \
        --sun-misc-unsafe-memory-access=allow \
        -Dlogback.configurationFile=${LOGGING_CONFIG_PATH} \
        -DdependencyTrack.logging.level=${LOGGING_LEVEL} \
        -jar ${WAR_FILENAME} \
        -context ${CONTEXT}" \
]

# Specify which port Dependency-Track listens on
EXPOSE 8080

# Add a healthcheck using the Dependency-Track version API
HEALTHCHECK --interval=30s --start-period=60s --timeout=5s CMD [ \
    "/bin/sh", "-c", \
    "curl -f -s --max-time 3 --noproxy '*' -o /dev/null http://127.0.0.1:8080${CONTEXT}health" \
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
