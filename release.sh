#!/usr/bin/env bash
# This script (for macOS) will release Dependency-Track

read -p "Are you sure you want to release (yes/no)? "
if ( [ "$REPLY" == "yes" ] ) then

read -p "Specify release version number (i.e. 3.0.0): "

export JAVA_HOME=`/usr/libexec/java_home -v 1.8`
export PATH=JAVA_HOME/bin:$PATH

REPO=owasp/dependency-track
VERSION=$REPLY


# Updates the version, commits, builds the war and executable war, and releases those two artifacts to GitHub
mvn versions:set -DnewVersion=$VERSION
git commit -m "Preparing to release $VERSION"
git push origin master
mvn clean package
mvn package -Dmaven.test.skip=true -P embedded-jetty -Dlogback.configuration.file=src/main/docker/logback.xml
mvn github-release:release


# Cleanup containers/images, build new image and push to Docker Hub
docker rm dependency-track
docker rmi $REPO:latest
docker rmi $REPO:$VERSION
docker build -f src/main/docker/Dockerfile -t $REPO:$VERSION -t $REPO:latest .
docker login
docker push $REPO

else
  echo 'Exit without release'
fi