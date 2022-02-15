FROM eclipse-temurin:11.0.14.1_1-jre-focal@sha256:246f0a07f7ba2c52b48d1879aa6f294d80619575f719ea31eaec0885560b803e AS jre-build

FROM debian:bullseye-20220125-slim@sha256:4c25ffa6ef572cf0d57da8c634769a08ae94529f7de5be5587ec8ce7b9b50f9c

# Arguments that can be passed at build time
# Directory names must end with / to avoid errors when ADDing and COPYing
ARG COMMIT_SHA
ARG APP_VERSION
ARG APP_DIR=/opt/owasp/dependency-track/
ARG DATA_DIR=/data/
ARG UID=1000
ARG GID=1000
ARG WAR_FILENAME=dependency-track-apiserver.jar

ENV TZ=Etc/UTC \
    # Dependency-Track's default logging level
    LOGGING_LEVEL=INFO \
    # Environment variables that can be passed at runtime
    JAVA_OPTIONS="-XX:+UseParallelGC -XX:MaxRAMPercentage=90.0" \
    # The web context defaults to the root. To override, supply an alternative context which starts with a / but does not end with one
    # Example: /dtrack
    CONTEXT="/" \
    # Injects the build-time ARG "WAR_FILENAME" as an environment variable that can be used in the CMD.
    WAR_FILENAME=${WAR_FILENAME} \
    # Set JAVA_HOME for the copied over JRE
    JAVA_HOME=/opt/java/openjdk \
    PATH="/opt/java/openjdk/bin:${PATH}" \
    LANG=C.UTF-8

COPY --from=jre-build /opt/java/openjdk $JAVA_HOME

# Copy the compiled WAR to the application directory created above
# Automatically creates the $APP_DIR directory
COPY ./target/${WAR_FILENAME} ${APP_DIR}

# Create the directory where Dependency-Track will store its data (${DATA_DIR}) and the external library directory (${EXTLIB_DIR})
# Create a user and assign home directory to a ${DATA_DIR}
# Ensure UID 1000 & GID 1000 own all the needed directories
RUN mkdir -p -m 770 ${DATA_DIR} \
    && addgroup --system --gid ${GID} dtrack || true \
    && adduser --system --disabled-login --ingroup dtrack --no-create-home --home ${DATA_DIR} --gecos "dtrack user" --shell /bin/false --uid ${UID} dtrack || true \
    && chown -R dtrack:0 ${DATA_DIR} ${APP_DIR} \
    && chmod -R g=u ${DATA_DIR} ${APP_DIR}

# Specify the user to run as (in numeric format for compatibility with Kubernetes/OpenShift's SCC)
USER ${UID}

# Specify the container working directory
WORKDIR ${APP_DIR}

# Launch Dependency-Track
CMD java ${JAVA_OPTIONS} -DdependencyTrack.logging.level=${LOGGING_LEVEL} -jar ${WAR_FILENAME} -context ${CONTEXT}

# Specify which port Dependency-Track listens on
EXPOSE 8080

# Add a healthcheck using the Dependency-Track version API
HEALTHCHECK --interval=5m --timeout=3s CMD wget --proxy off -q -O /dev/null http://127.0.0.1:8080${CONTEXT}api/version || exit 1

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
