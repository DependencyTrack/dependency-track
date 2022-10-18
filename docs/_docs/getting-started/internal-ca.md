---
title: Internal Certificate Authorities
category: Getting Started
chapter: 1
order: 11
---

Many organizations use their own [certificate authority](https://en.wikipedia.org/wiki/Certificate_authority) (CA) to 
sign TLS certificates for internal use. Similar to web browsers, the Java Runtime Environment (JRE) per default trusts 
only a certain selection of public CAs. When connecting to a website that serves a TLS certificate that wasn't signed 
by any of those trusted CAs, the browser will display a security warning to the user. 

The JRE behaves a little different, in that it will cause the connection to fail and raise an exception with the 
following message:

```
PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
```

This error is commonly observed when Dependency-Track is configured to connect to internal systems over TLS,
and those systems serve TLS certificates signed by the organization's internal CA. Most common situations include:

* Dependency-Track is configured to use a HTTP proxy to connect to external services
* Dependency-Track is configured to use an internal identity provider for OpenID Connect

The issue can be addressed by including the internal CA in the so-called *truststore* of the JRE.
For containerized deployment of Dependency-Track, this can be achieved as follows:

1. Export the default truststore from the API server image
   ```shell
   container_id=$(docker run -d --rm dependencytrack/apiserver:latest)
   docker cp "$container_id:/opt/java/openjdk/lib/security/cacerts" .
   docker stop $container_id
   ```

2. Add the certificate of the internal CA to the truststore
   ```shell
   docker run --rm -it -v "$(pwd):/work" eclipse-temurin:11-jre \
      keytool -keystore /work/cacerts -storepass changeit \
      -noprompt -trustcacerts -importcert -alias acme-inc \
      -file /work/acme-inc.crt
   ```

3. Mount the modified truststore into the container
   ```yaml
   # docker-compose.yml
   services:
     dtrack-apiserver:
       # ...
       volumes:
       - "./cacerts:/opt/java/openjdk/lib/security/cacerts:ro"
   ```

4. Recreate the API server container for the volume mount to take effect
   ```shell
   docker-compose up -d dtrack-apiserver
   ```
