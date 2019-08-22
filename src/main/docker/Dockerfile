FROM alpine:3.10
LABEL maintainer="steve.springett@owasp.org"
LABEL vendor="OWASP"

# Arguments that can be passed at build time
ARG APP_DIR=/opt/owasp/dependency-track
ARG DATA_DIR=/data
ARG EXTLIB_DIR=/extlib
ARG USER=dtrack

RUN apk --no-cache add openjdk8-jre-base \
# Create the application directory where Dependency-Track will be installed and the external library directory
	&& mkdir -p "$APP_DIR" "$DATA_DIR" "$EXTLIB_DIR"

# Copy the compiled WAR to the application directory created above
COPY ./target/dependency-track-embedded.war "$APP_DIR"
# Download optional JDBC drivers to the external library directory
ADD https://repo1.maven.org/maven2/org/postgresql/postgresql/42.2.5/postgresql-42.2.5.jar "$EXTLIB_DIR"
ADD https://repo1.maven.org/maven2/mysql/mysql-connector-java/5.1.47/mysql-connector-java-5.1.47.jar "$EXTLIB_DIR"
ADD https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/7.1.3.jre8-preview/mssql-jdbc-7.1.3.jre8-preview.jar "$EXTLIB_DIR"

# Create a user and assign home directory to a non-standard path
RUN adduser -h "$DATA_DIR" -s bash -D "$USER" \
# Ensure "$USER" have access to all the needed directories
    && chown -R "$USER":"$USER" "$APP_DIR" "$EXTLIB_DIR" \
    && chmod -R 770 "$APP_DIR" "$DATA_DIR" "$EXTLIB_DIR"

# Specify the user to run commands as
USER "$USER"
WORKDIR ${APP_DIR}

# Launch Dependency-Track
CMD java $JAVA_OPTIONS -DdependencyTrack.logging.level=$LOGGING_LEVEL -jar dependency-track-embedded.war

EXPOSE 8080

# The default logging level
ENV LOGGING_LEVEL=INFO
# Environment variables that can be passed at runtime
ENV JAVA_OPTIONS="-XX:+UnlockExperimentalVMOptions -XX:+UseCGroupMemoryLimitForHeap -Xmx4G"

#VOLUME "$DATA_DIR"
