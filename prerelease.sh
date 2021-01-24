#!/usr/bin/env bash
# This script (for macOS) will release Dependency-Track

export JAVA_HOME=`/usr/libexec/java_home -v 11`
export PATH=JAVA_HOME/bin:$PATH

mvn clean
mvn package -Dmaven.test.skip=true -P clean-exclude-wars -P embedded-jetty -Dlogback.configuration.file=src/main/docker/logback.xml
mvn clean -P clean-exclude-wars
mvn package -Dmaven.test.skip=true -P embedded-jetty -P bundle-ui -Dlogback.configuration.file=src/main/docker/logback.xml
mvn clean -P clean-exclude-wars
mvn package -Dmaven.test.skip=true -P bundle-ui
mvn clean -P clean-exclude-wars
mvn net.nicoulaj.maven.plugins:checksum-maven-plugin:files
mvn github-release:release
