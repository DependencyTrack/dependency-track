#!/usr/bin/env bash
# This script (for macOS) will release Dependency-Track

export JAVA_HOME=`/usr/libexec/java_home -v 1.8`
export PATH=JAVA_HOME/bin:$PATH

mvn clean package
mvn package -Dmaven.test.skip=true -P embedded-jetty -Dlogback.configuration.file=src/main/docker/logback.xml
mvn net.nicoulaj.maven.plugins:checksum-maven-plugin:files
mvn github-release:release