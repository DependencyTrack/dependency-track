# =============================================================================
# Stage 1: Build from source with Maven
# This stage compiles your custom changes into an executable JAR
# =============================================================================
FROM maven:3.9.8-eclipse-temurin-21 AS build

WORKDIR /build

# Copy pom.xml first for better layer caching
COPY pom.xml .

# Download dependencies (with fallback)
RUN mvn -q -e -U -Penhance dependency:go-offline || mvn -q -e -U dependency:go-offline

# Copy source code
COPY . .

# Build executable JAR with embedded Jetty
# Using official profile combination from DEVELOPING.md
RUN mvn -q -e clean package \
    -P quick \
    -P clean-exclude-wars \
    -P enhance \
    -P embedded-jetty \
    -DskipTests \
    -Dlogback.configuration.file=src/main/docker/logback.xml

# =============================================================================
# Stage 2: Production runtime
# Based on official DPT Dockerfile patterns for security and reliability
# =============================================================================
FROM eclipse-temurin:21-jre-alpine AS runtime

# OCI Image Labels (following official DPT pattern)
LABEL org.opencontainers.image.title="Dependency-Track API Server" \
      org.opencontainers.image.description="Custom build of Dependency-Track API Server" \
      org.opencontainers.image.vendor="Custom Build" \
      org.opencontainers.image.source="https://github.com/DependencyTrack/dependency-track"

# Environment variables for configuration
ENV JAVA_OPTIONS="" \
    EXTRA_JAVA_OPTIONS="" \
    LOGGING_CONFIG_PATH="logback.xml" \
    LOGGING_LEVEL="INFO" \
    # Database configuration (override for external DB)
    ALPINE_DATABASE_MODE="embedded" \
    ALPINE_DATABASE_DRIVER="org.h2.Driver" \
    ALPINE_DATABASE_URL="jdbc:h2:~/.dependency-track/db" \
    ALPINE_DATABASE_USERNAME="sa" \
    ALPINE_DATABASE_PASSWORD=""

# Create non-root user for security (matching official UID 1000)
RUN addgroup -g 1000 dtrack && \
    adduser -D -u 1000 -G dtrack -h /opt/dtrack dtrack

WORKDIR /opt/dtrack

# Create data directory with proper ownership
RUN mkdir -p /opt/dtrack/.dependency-track && \
    chown -R dtrack:dtrack /opt/dtrack

# Copy artifacts from build stage
COPY --from=build --chown=dtrack:dtrack /build/target/dependency-track-apiserver.jar ./dependency-track-apiserver.jar
COPY --from=build --chown=dtrack:dtrack /build/src/main/docker/logback.xml ./logback.xml
COPY --from=build --chown=dtrack:dtrack /build/src/main/docker/logback-json.xml ./logback-json.xml

# Switch to non-root user
USER dtrack

# Volume for persistent data
VOLUME /opt/dtrack/.dependency-track

EXPOSE 8080

# Healthcheck for container orchestration
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Entrypoint with configurable options
ENTRYPOINT ["sh", "-c", "exec java \
    -XX:+UseParallelGC \
    -XX:+UseStringDeduplication \
    -XX:MaxRAMPercentage=90 \
    --add-opens java.base/java.util.concurrent=ALL-UNNAMED \
    ${JAVA_OPTIONS} \
    ${EXTRA_JAVA_OPTIONS} \
    -Dlogback.configurationFile=${LOGGING_CONFIG_PATH} \
    -DdependencyTrack.logging.level=${LOGGING_LEVEL} \
    -Dalpine.database.mode=${ALPINE_DATABASE_MODE} \
    -Dalpine.database.driver=${ALPINE_DATABASE_DRIVER} \
    -Dalpine.database.url=${ALPINE_DATABASE_URL} \
    -Dalpine.database.username=${ALPINE_DATABASE_USERNAME} \
    -Dalpine.database.password=${ALPINE_DATABASE_PASSWORD} \
    -jar dependency-track-apiserver.jar \
    -context /"]
