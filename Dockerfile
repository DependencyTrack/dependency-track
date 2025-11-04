FROM maven:3.9.8-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -q -e -U -Penhance dependency:go-offline || mvn -q -e -U dependency:go-offline
COPY . .
# Produce executable Jar with embedded Jetty (official profile combination)
RUN mvn -q -e package -P quick -P enhance -P embedded-jetty -Dprotobuf.skip=true -Dlogback.configuration.file=src/main/docker/logback.xml

FROM eclipse-temurin:21-jre AS runtime
ENV JAVA_OPTIONS="-XX:+UseParallelGC -XX:+UseStringDeduplication -XX:MaxRAMPercentage=85" \
	LOGGING_LEVEL=INFO
WORKDIR /opt/dtrack
RUN mkdir -p /root/.dependency-track
COPY --from=build /build/target/dependency-track-apiserver.jar ./dependency-track-apiserver.jar
COPY --from=build /build/src/main/docker/logback.xml ./logback.xml
COPY --from=build /build/src/main/docker/logback-json.xml ./logback-json.xml
EXPOSE 8080
ENTRYPOINT ["java","-XX:+UseParallelGC","-XX:+UseStringDeduplication","-XX:MaxRAMPercentage=85","--add-opens","java.base/java.util.concurrent=ALL-UNNAMED","-Dlogback.configurationFile=logback.xml","-DdependencyTrack.logging.level=INFO","-jar","dependency-track-apiserver.jar","-context","/"]
