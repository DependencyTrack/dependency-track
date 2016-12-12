FROM tomcat:8.0-jre8-alpine
MAINTAINER Steve Springett, https://github.com/stevespringett

# Remove Tomcat default deployed webapps
RUN ["rm", "-fr", "/usr/local/tomcat/webapps/docs"]
RUN ["rm", "-fr", "/usr/local/tomcat/webapps/examples"]
RUN ["rm", "-fr", "/usr/local/tomcat/webapps/host-manager"]
RUN ["rm", "-fr", "/usr/local/tomcat/webapps/manager"]
RUN ["rm", "-fr", "/usr/local/tomcat/webapps/ROOT"]

COPY ./target/dependency-track.war /usr/local/tomcat/webapps/ROOT.war

EXPOSE 8080

CMD ["catalina.sh", "run"]