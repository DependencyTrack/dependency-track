FROM openjdk:8-jre-alpine
MAINTAINER Steve Springett, https://github.com/stevespringett

# Create the application directory where Dependency-Track will be installed
RUN ["mkdir", "-p", "/opt/owasp/dependency-track"]

# Copy the compiled WAR to the application directory created above
COPY ./target/dependency-track.war /opt/owasp/dependency-track

EXPOSE 8080

# Launch Dependency-Track
CMD ["java", "-jar", "/opt/owasp/dependency-track/dependency-track.war"]