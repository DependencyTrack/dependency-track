FROM openjdk:8-jre-alpine
LABEL maintainer="steve.springett@owasp.org"
LABEL vendor="OWASP"

ARG APP_DIR=/opt/owasp/dependency-track
ARG DATA_DIR=/data
ARG USER=dtrack

# Create the application directory where Dependency-Track will be installed
RUN mkdir -p ${APP_DIR}

# Create a user and assign home directory to a non-standard path
RUN adduser -h ${DATA_DIR} -s bash -D ${USER}

# Specify the user to run commands as
USER ${USER}

# Copy the compiled WAR to the application directory created above
COPY ./target/dependency-track-embedded.war ${APP_DIR}

VOLUME ${DATA_DIR}

EXPOSE 8080

# Launch Dependency-Track
WORKDIR ${APP_DIR}
CMD java -jar dependency-track-embedded.war