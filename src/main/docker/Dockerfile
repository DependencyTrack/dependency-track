FROM eclipse-temurin:21.0.5_11-jre-jammy@sha256:5f8358c9d5615c18e95728e8b8528bda7ff40a7a5da2ac9a35b7a01f5d9b231a AS jre-build

FROM debian:stable-slim@sha256:5f21ebd358442f40099c997a3f4db906a7b1bd872249e67559f55de654b55d3b

# Arguments that can be passed at build time
# Directory names must end with / to avoid errors when ADDing and COPYing
ARG COMMIT_SHA=unknown
ARG APP_VERSION=0.0.0
ARG APP_DIR=/opt/owasp/dependency-track/
ARG DATA_DIR=/data/
ARG UID=1000
ARG GID=1000
ARG WAR_FILENAME=dependency-track-apiserver.jar

ENV TZ=Etc/UTC \
    # Dependency-Track's default logging level
    LOGGING_LEVEL=INFO \
    # JVM Options that are passed at runtime by default
    JAVA_OPTIONS="-XX:+UseParallelGC -XX:+UseStringDeduplication -XX:MaxRAMPercentage=90.0" \
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
    && addgroup --system --gid ${GID} dtrack || true \
    && adduser --system --disabled-login --ingroup dtrack --no-create-home --home ${DATA_DIR} --gecos "dtrack user" --shell /bin/false --uid ${UID} dtrack || true \
    && chown -R dtrack:0 ${DATA_DIR} ${APP_DIR} \
    && chmod -R g=u ${DATA_DIR} ${APP_DIR} \
    \
    # Install wget for health check
    && apt-get -yqq update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yqq --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

# Copy JRE from temurin base image
COPY --from=jre-build /opt/java/openjdk $JAVA_HOME

# Copy the compiled WAR to the application directory created above
COPY ./target/${WAR_FILENAME} ./src/main/docker/logback-json.xml ${APP_DIR}

# Specify the user to run as (in numeric format for compatibility with Kubernetes/OpenShift's SCC)
USER ${UID}

# Specify the container working directory
WORKDIR ${APP_DIR}

# Launch Dependency-Track
CMD exec java ${JAVA_OPTIONS} ${EXTRA_JAVA_OPTIONS} \
    --add-opens java.base/java.util.concurrent=ALL-UNNAMED \
    -Dlogback.configurationFile=${LOGGING_CONFIG_PATH} \
    -DdependencyTrack.logging.level=${LOGGING_LEVEL} \
    -jar ${WAR_FILENAME} \
    -context ${CONTEXT}

# Specify which port Dependency-Track listens on
EXPOSE 8080

# Add a healthcheck using the Dependency-Track version API
HEALTHCHECK --interval=30s --start-period=60s --timeout=3s CMD wget -t 1 -T 3 --no-proxy -q -O /dev/null http://127.0.0.1:8080${CONTEXT}health || exit 1

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
