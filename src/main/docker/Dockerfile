FROM adoptopenjdk/openjdk11:alpine-jre
LABEL maintainer="steve.springett@owasp.org"
LABEL vendor="OWASP"

# Arguments that can be passed at build time
ARG APP_DIR=/opt/owasp/dependency-track
ARG DATA_DIR=/data
ARG USER=dtrack
ARG EXT_LIB=/extlib

# The default logging level
ENV LOGGING_LEVEL=INFO

# Environment variables that can be passed at runtime
ENV JAVA_OPTIONS="-Xmx4G"

# Create the application directory where Dependency-Track will be installed
RUN mkdir -p ${APP_DIR}

# Create the external library directory
RUN mkdir -p ${EXT_LIB}

# Create a user and assign home directory to a non-standard path
RUN adduser -h ${DATA_DIR} -s bash -D ${USER}

# Copy the compiled WAR to the application directory created above
COPY ./target/dependency-track-embedded.war ${APP_DIR}

VOLUME ${DATA_DIR}

# Download optional JDBC drivers to the external library directory
ADD https://repo1.maven.org/maven2/org/postgresql/postgresql/42.2.5/postgresql-42.2.5.jar ${EXT_LIB}
ADD https://repo1.maven.org/maven2/mysql/mysql-connector-java/5.1.47/mysql-connector-java-5.1.47.jar ${EXT_LIB}
ADD https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/7.1.3.jre8-preview/mssql-jdbc-7.1.3.jre8-preview.jar ${EXT_LIB}
RUN chown -f -R ${USER}:${USER} ${EXT_LIB}

# Specify the user to run commands as
USER ${USER}

EXPOSE 8080

# Launch Dependency-Track
WORKDIR ${APP_DIR}
CMD java $JAVA_OPTIONS -DdependencyTrack.logging.level=$LOGGING_LEVEL -jar dependency-track-embedded.war
