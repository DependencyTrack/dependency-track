FROM adoptopenjdk/openjdk8:alpine-jre
LABEL maintainer="steve.springett@owasp.org"
LABEL vendor="OWASP"

# Arguments that can be passed at build time
# Directory names must end with / to avoid errors when ADDing and COPYing
ARG APP_DIR=/opt/owasp/dependency-track/
ARG DATA_DIR=/data/
ARG EXTLIB_DIR=/extlib/
ARG USERNAME=dtrack

# Create the directory where Dependency-Track will store its data (${DATA_DIR}) and the external library directory (${EXTLIB_DIR})
# Create a user and assign home directory to a ${DATA_DIR}
# Download optional JDBC drivers to the external library directory
# Ensure UID 1000 & GID 1000 own all the needed directories
RUN mkdir -p -m 770 ${DATA_DIR} ${EXTLIB_DIR} \
    && adduser -D -h ${DATA_DIR} -u 1000 ${USERNAME} \
    && wget -P ${EXTLIB_DIR} https://repo1.maven.org/maven2/org/postgresql/postgresql/42.2.5/postgresql-42.2.5.jar \
    && wget -P ${EXTLIB_DIR} https://repo1.maven.org/maven2/mysql/mysql-connector-java/5.1.47/mysql-connector-java-5.1.47.jar \
    && wget -P ${EXTLIB_DIR} https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/7.1.3.jre8-preview/mssql-jdbc-7.1.3.jre8-preview.jar \
    && chown -R ${USERNAME}:${USERNAME} ${DATA_DIR} ${EXTLIB_DIR}

# Copy the compiled WAR to the application directory created above
# Automatically creates the $APP_DIR directory
COPY --chown=1000 ./target/dependency-track-embedded.war ${APP_DIR}

# Specify the user to run as (in numeric format for compatibility with Kubernetes/OpenShift's SCC)
USER 1000

# Specify the container working directory
WORKDIR ${APP_DIR}

# Launch Dependency-Track
CMD java $JAVA_OPTIONS -DdependencyTrack.logging.level=$LOGGING_LEVEL -jar dependency-track-embedded.war -context ${CONTEXT}

# Specify which port Dependency-Track listens on
EXPOSE 8080

# Dependency-Track's default logging level
ENV LOGGING_LEVEL=INFO

# Environment variables that can be passed at runtime
ENV JAVA_OPTIONS="-XX:MaxRAMPercentage=90.0"

# The web context defaults to the root. To override, supply an alternative context which starts with a / but does not end with one
# Example: /dtrack
ENV CONTEXT=""

# Add a healthcheck using the Dependency-Track version API
HEALTHCHECK --interval=5m --timeout=3s CMD wget -q -O /dev/null http://127.0.0.1:8080${CONTEXT}/api/version || exit 1
