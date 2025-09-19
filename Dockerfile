
FROM amazonlinux:2023 AS build
WORKDIR /app

# Install Java 21, Maven, Git, and Protobuf
RUN yum -y install java-21-amazon-corretto-devel maven git tar gzip protobuf-compiler \
    && java -version \
    && javac -version \
    && mvn -version \
    && protoc --version \
    && yum clean all \
    && rm -rf /var/cache/yum

ENV JAVA_HOME=/usr/lib/jvm/java-21-amazon-corretto
ENV PATH="$JAVA_HOME/bin:$PATH"

COPY . .
RUN mvn dependency:go-offline -B




# Build Dependency-Track (skip tests, include embedded profile)
RUN mvn clean package -DskipTests -Pembedded-jetty,enhance



FROM amazonlinux:2023 AS runtime
WORKDIR /app

RUN yum -y install java-21-amazon-corretto \
    && java -version \
    && yum clean all \
    && rm -rf /var/cache/yum

# Copy the actual embedded JAR (handles version suffixes)
COPY --from=build /app/target/dependency-track-apiserver.jar app.jar

# Expose HTTP port
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]


