---
title: Configuration - API Server
category: Getting Started
chapter: 1
order: 7
---
<!--
  GENERATED. DO NOT EDIT.

  Generated with: jbang gen-config-docs@DependencyTrack --template ./dev/scripts/config-docs.md.peb --output docs/_docs/getting-started/configuration-apiserver.md ./src/main/resources/application.properties
-->

The central configuration file `application.properties` resides in the classpath of the WAR by default.
This configuration file controls many performance tuning parameters but is most useful for defining
optional external database sources, directory services (LDAP), and proxy settings.

For containerized deployments, the properties defined in the configuration file can also be specified
as environment variables. All environment variables are upper case with periods (.) replaced with underscores (_).
Refer to the [Docker instructions]({{ site.baseurl }}{% link _docs/getting-started/deploy-docker.md %}) for
configuration examples using environment variables.

Dependency-Track administrators are highly encouraged to create a copy of this file in the
Dependency-Track data directory and customize it prior to deploying to production.


> The default embedded H2 database is designed to quickly evaluate and experiment with Dependency-Track.
> Do not use the embedded H2 database in production environments.
>
> See: [Database Support]({{ site.baseurl }}{% link _docs/getting-started/database-support.md %}).


To start Dependency-Track using custom configuration, add the system property
`alpine.application.properties` when executing. For example:

```bash
-Dalpine.application.properties=~/.dependency-track/application.properties
```

### Proxy Configuration

Proxy support can be configured in one of two ways, using the proxy settings defined
in `application.properties` or through environment variables. By default, the system
will attempt to read the `https_proxy`, `http_proxy` and `no_proxy` environment variables. If one
of these are set, Dependency-Track will use them automatically.

`no_proxy` specifies URLs that should be excluded from proxying.
This can be a comma-separated list of hostnames, domain names, or a mixture of both.
If a port number is specified for a URL, only the requests with that port number to that URL will be excluded from proxying.
`no_proxy` can also set to be a single asterisk ('*') to match all hosts.

Dependency-Track supports proxies that require BASIC, DIGEST, and NTLM authentication.

### Logging Levels

Logging levels (INFO, WARN, ERROR, DEBUG, TRACE) can be specified by passing the level
to the `dependencyTrack.logging.level` system property on startup. For example, the
following command will start Dependency-Track (embedded) with DEBUG logging:

```bash
java -Xmx4G -DdependencyTrack.logging.level=DEBUG -jar dependency-track-embedded.war
```

For Docker deployments, simply set the `LOGGING_LEVEL` environment variable to one of
INFO, WARN, ERROR, DEBUG, or TRACE.

### Secret Key

Dependency-Track will encrypt certain confidential data (e.g. access tokens for external service providers) with AES256
prior to storing it in the database. The secret key used for encrypting and decrypting will be automatically generated
when Dependency-Track starts for the first time, and is placed in `<alpine.data.directory>/keys/secret.key`
(`/data/.dependency-track/keys/secret.key` for containerized deployments).

Starting with Dependency-Track 4.7, it is possible to change the location of the secret key via the `alpine.secret.key.path`
property. This makes it possible to use Kubernetes secrets for example, to mount secrets into the custom location.

Secret keys may be generated manually upfront instead of relying on Dependency-Track to do it. This can be achieved
with OpenSSL like this:

```shell
openssl rand 32 > secret.key
```

> Note that the default key format has changed in version 4.7. While existing keys using the old format will continue
> to work, keys for new instances will be generated in the new format. Old keys may be converted using the following
> [JShell](https://docs.oracle.com/en/java/javase/17/jshell/introduction-jshell.html) script:
> ```java
> import java.io.ObjectInputStream;
> import java.nio.file.Files;
> import java.nio.file.Paths;
> import javax.crypto.SecretKey;
> String inputFilePath = System.getProperty("secret.key.input")
> String outputFilePath = System.getProperty("secret.key.output");
> SecretKey secretKey = null;
> System.out.println("Reading old key from " + inputFilePath);
> try (var fis = Files.newInputStream(Paths.get(inputFilePath));
>      var ois = new ObjectInputStream(fis)) {
>     secretKey = (SecretKey) ois.readObject();
> }
> System.out.println("Writing new key to " + outputFilePath);
> try (var fos = Files.newOutputStream(Paths.get(outputFilePath))) {
>     fos.write(secretKey.getEncoded());
> }
> /exit
> ```
> Example execution:
> ```shell
> jshell -R"-Dsecret.key.input=$HOME/.dependency-track/keys/secret.key" -R"-Dsecret.key.output=secret.key.new" convert-key.jsh
> ```

---

## Reference

<ul>

  <li><a href="#analyzers">Analyzers</a></li>

  <li><a href="#cors">CORS</a></li>

  <li><a href="#database">Database</a></li>

  <li><a href="#general">General</a></li>

  <li><a href="#http">HTTP</a></li>

  <li><a href="#ldap">LDAP</a></li>

  <li><a href="#observability">Observability</a></li>

  <li><a href="#openid-connect">OpenID Connect</a></li>

  <li><a href="#other">Other</a></li>

  <li><a href="#task-execution">Task Execution</a></li>

</ul>


### Analyzers

#### ossindex.retry.backoff.max.duration.ms

Defines the maximum duration in milliseconds to wait before attempting the next retry.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">600000</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">OSSINDEX_RETRY_BACKOFF_MAX_DURATION_MS</td>
    </tr>
  </tbody>
</table>

#### ossindex.retry.backoff.multiplier

Defines the multiplier for the exponential backoff retry strategy.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">2</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">OSSINDEX_RETRY_BACKOFF_MULTIPLIER</td>
    </tr>
  </tbody>
</table>

#### ossindex.retry.max.attempts

Defines the maximum amount of retries to perform for each request to the OSS Index API.
Retries are performed with increasing delays between attempts using an exponential backoff strategy.
The initial duration defined in ossindex.retry.backoff.initial.duration.ms will be
multiplied with the value defined in [`ossindex.retry.backoff.multiplier`](#ossindexretrybackoffmultiplier) after each retry attempt,
until the maximum duration defined in [`ossindex.retry.backoff.max.duration.ms`](#ossindexretrybackoffmaxdurationms) is reached.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">10</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">OSSINDEX_RETRY_MAX_ATTEMPTS</td>
    </tr>
  </tbody>
</table>

#### repo.meta.analyzer.cacheStampedeBlocker.enabled

This flag activate the cache stampede blocker for the repository meta analyzer allowing to handle high concurrency workloads when there
is a high ratio of duplicate components which can cause unnecessary external calls and index violation on PUBLIC.REPOSITORY_META_COMPONENT_COMPOUND_IDX during cache population.
The default value is true.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">true</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">REPO_META_ANALYZER_CACHESTAMPEDEBLOCKER_ENABLED</td>
    </tr>
  </tbody>
</table>

#### repo.meta.analyzer.cacheStampedeBlocker.lock.buckets

The cache stampede blocker use a striped (partitioned) lock to distribute locks across keys.
This parameter defines the number of bucket used by the striped lock. The lock used for a given key is derived from the key hashcode and number of buckets.
This value should be set according to your portfolio profile (i.e. number of projects and proportion of duplicates).
Too few buckets and an unbalanced portfolio (i.e. high number of purl going to the same partition) can lead to forced serialization
Too much buckets can lead to unnecessary memory usage. Note that the memory footprint of Striped Lock is 32 * (nbOfBuckets * 1) Bytes.
A value between 1_000 (~32 KB) and 1_000_000 (~32 MB) seems reasonable.
The default value is 1000 (~32KB).


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">1000</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">REPO_META_ANALYZER_CACHESTAMPEDEBLOCKER_LOCK_BUCKETS</td>
    </tr>
  </tbody>
</table>

#### repo.meta.analyzer.cacheStampedeBlocker.max.attempts

Defines the maximum number of attempts used by Resilience4J for exponential backoff retry regarding repo meta analyzer cache loading per key.
The default value is 10.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">10</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">REPO_META_ANALYZER_CACHESTAMPEDEBLOCKER_MAX_ATTEMPTS</td>
    </tr>
  </tbody>
</table>

#### snyk.retry.backoff.initial.duration.ms

Defines the duration in milliseconds to wait before attempting the first retry.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">1000</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">SNYK_RETRY_BACKOFF_INITIAL_DURATION_MS</td>
    </tr>
  </tbody>
</table>

#### snyk.retry.backoff.max.duration.ms

Defines the maximum duration in milliseconds to wait before attempting the next retry.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">60000</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">SNYK_RETRY_BACKOFF_MAX_DURATION_MS</td>
    </tr>
  </tbody>
</table>

#### snyk.retry.backoff.multiplier

Defines the multiplier for the exponential backoff retry strategy.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">2</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">SNYK_RETRY_BACKOFF_MULTIPLIER</td>
    </tr>
  </tbody>
</table>

#### snyk.retry.max.attempts

Defines the maximum amount of retries to perform for each request to the Snyk API.
Retries are performed with increasing delays between attempts using an exponential backoff strategy.
The initial duration defined in [`snyk.retry.backoff.initial.duration.ms`](#snykretrybackoffinitialdurationms) will be
multiplied with the value defined in [`snyk.retry.backoff.multiplier`](#snykretrybackoffmultiplier) after each retry attempt,
until the maximum duration defined in [`snyk.retry.backoff.max.duration.ms`](#snykretrybackoffmaxdurationms) is reached.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">10</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">SNYK_RETRY_MAX_ATTEMPTS</td>
    </tr>
  </tbody>
</table>

#### snyk.thread.pool.size

Defines the size of the thread pool used to perform requests to the Snyk API in parallel.
The thread pool will only be used when Snyk integration is enabled.
A high number may result in quicker exceeding of API rate limits,
while a number that is too low may result in vulnerability analyses taking longer.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">10</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">SNYK_THREAD_POOL_SIZE</td>
    </tr>
  </tbody>
</table>

#### trivy.retry.backoff.initial.duration.ms

Defines the duration in milliseconds to wait before attempting the first retry.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">1000</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">TRIVY_RETRY_BACKOFF_INITIAL_DURATION_MS</td>
    </tr>
  </tbody>
</table>

#### trivy.retry.backoff.max.duration.ms

Defines the maximum duration in milliseconds to wait before attempting the next retry.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">60000</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">TRIVY_RETRY_BACKOFF_MAX_DURATION_MS</td>
    </tr>
  </tbody>
</table>

#### trivy.retry.backoff.multiplier

Defines the multiplier for the exponential backoff retry strategy.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">2</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">TRIVY_RETRY_BACKOFF_MULTIPLIER</td>
    </tr>
  </tbody>
</table>

#### trivy.retry.max.attempts

Defines the maximum amount of retries to perform for each request to the Trivy API.
Retries are performed with increasing delays between attempts using an exponential backoff strategy.
The initial duration defined in [`trivy.retry.backoff.initial.duration.ms`](#trivyretrybackoffinitialdurationms) will be
multiplied with the value defined in [`trivy.retry.backoff.multiplier`](#trivyretrybackoffmultiplier) after each retry attempt,
until the maximum duration defined in [`trivy.retry.backoff.max.duration.ms`](#trivyretrybackoffmaxdurationms) is reached.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">10</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">TRIVY_RETRY_MAX_ATTEMPTS</td>
    </tr>
  </tbody>
</table>



### CORS

#### alpine.cors.allow.credentials

Controls the content of the `Access-Control-Allow-Credentials` response header.
<br/>
Has no effect when [`alpine.cors.enabled`](#alpinecorsenabled) is `false`.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">true</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_CORS_ALLOW_CREDENTIALS</td>
    </tr>
  </tbody>
</table>

#### alpine.cors.allow.headers

Controls the content of the `Access-Control-Allow-Headers` response header.
<br/>
Has no effect when [`alpine.cors.enabled`](#alpinecorsenabled) is `false`.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">Origin, Content-Type, Authorization, X-Requested-With, Content-Length, Accept, Origin, X-Api-Key, X-Total-Count, *</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_CORS_ALLOW_HEADERS</td>
    </tr>
  </tbody>
</table>

#### alpine.cors.allow.methods

Controls the content of the `Access-Control-Allow-Methods` response header.
<br/>
Has no effect when [`alpine.cors.enabled`](#alpinecorsenabled) is `false`.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">GET POST PUT DELETE OPTIONS</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_CORS_ALLOW_METHODS</td>
    </tr>
  </tbody>
</table>

#### alpine.cors.allow.origin

Controls the content of the `Access-Control-Allow-Origin` response header.
<br/>
Has no effect when [`alpine.cors.enabled`](#alpinecorsenabled) is `false`.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">*</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_CORS_ALLOW_ORIGIN</td>
    </tr>
  </tbody>
</table>

#### alpine.cors.enabled

Defines whether [Cross Origin Resource Sharing](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
(CORS) headers shall be included in REST API responses.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">true</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_CORS_ENABLED</td>
    </tr>
  </tbody>
</table>

#### alpine.cors.expose.headers

Controls the content of the `Access-Control-Expose-Headers` response header.
<br/>
Has no effect when [`alpine.cors.enabled`](#alpinecorsenabled) is `false`.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">Origin, Content-Type, Authorization, X-Requested-With, Content-Length, Accept, Origin, X-Api-Key, X-Total-Count</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_CORS_EXPOSE_HEADERS</td>
    </tr>
  </tbody>
</table>

#### alpine.cors.max.age

Controls the content of the `Access-Control-Max-Age` response header.
<br/>
Has no effect when [`alpine.cors.enabled`](#alpinecorsenabled) is `false`.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">3600</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_CORS_MAX_AGE</td>
    </tr>
  </tbody>
</table>



### Database

#### alpine.database.mode

Defines the database mode of operation.
In server mode, the database will listen for connections from remote
hosts. In embedded mode, the system will be more secure and slightly
faster. External mode should be used when utilizing an external
database server (i.e. mysql, postgresql, etc).


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">enum</td>
    </tr>
    <tr>
      <th style="text-align: right">Valid Values</th>
      <td style="border-width: 0">[server, embedded, external]</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">embedded</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_MODE</td>
    </tr>
  </tbody>
</table>

#### alpine.database.password

Specifies the password to use when authenticating to the database.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_PASSWORD</td>
    </tr>
  </tbody>
</table>

#### alpine.database.password.file

Specifies a path to the file holding the database password.
To be used as alternative to [`alpine.database.password`](#alpinedatabasepassword).


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_PASSWORD_FILE</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.enabled

Specifies if the database connection pool is enabled.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">true</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_ENABLED</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.idle.timeout

This property controls the maximum amount of time that a connection is
allowed to sit idle in the pool.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">300000</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_IDLE_TIMEOUT</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.max.lifetime

This property controls the maximum lifetime of a connection in the pool.
An in-use connection will never be retired, only when it is closed will
it then be removed.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">600000</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_MAX_LIFETIME</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.max.size

This property controls the maximum size that the pool is allowed to reach,
including both idle and in-use connections.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">20</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_MAX_SIZE</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.min.idle

This property controls the minimum number of idle connections in the pool.
This value should be equal to or less than [`alpine.database.pool.max.size`](#alpinedatabasepoolmaxsize).
Warning: If the value is less than [`alpine.database.pool.max.size`](#alpinedatabasepoolmaxsize),
[`alpine.database.pool.idle.timeout`](#alpinedatabasepoolidletimeout) will have no effect.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">10</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_MIN_IDLE</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.nontx.idle.timeout

Overwrite [`alpine.database.pool.idle.timeout`](#alpinedatabasepoolidletimeout) for the non-transactional connection pool.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_NONTX_IDLE_TIMEOUT</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.nontx.max.lifetime

Overwrite [`alpine.database.pool.max.lifetime`](#alpinedatabasepoolmaxlifetime) for the non-transactional connection pool.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_NONTX_MAX_LIFETIME</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.nontx.max.size

Overwrite [`alpine.database.pool.max.size`](#alpinedatabasepoolmaxsize) for the non-transactional connection pool.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_NONTX_MAX_SIZE</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.nontx.min.idle

Overwrite [`alpine.database.pool.min.idle`](#alpinedatabasepoolminidle) for the non-transactional connection pool.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_NONTX_MIN_IDLE</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.tx.idle.timeout

Overwrite [`alpine.database.pool.idle.timeout`](#alpinedatabasepoolidletimeout) for the transactional connection pool.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_TX_IDLE_TIMEOUT</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.tx.max.lifetime

Overwrite [`alpine.database.pool.max.lifetime`](#alpinedatabasepoolmaxlifetime) for the transactional connection pool.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_TX_MAX_LIFETIME</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.tx.max.size

Overwrite [`alpine.database.pool.max.size`](#alpinedatabasepoolmaxsize) for the transactional connection pool.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_TX_MAX_SIZE</td>
    </tr>
  </tbody>
</table>

#### alpine.database.pool.tx.min.idle

Overwrite [`alpine.database.pool.min.idle`](#alpinedatabasepoolminidle) for the transactional connection pool.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_POOL_TX_MIN_IDLE</td>
    </tr>
  </tbody>
</table>

#### alpine.database.port

Defines the TCP port to use when [`alpine.database.mode`](#alpinedatabasemode) is set to 'server'.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">9092</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_PORT</td>
    </tr>
  </tbody>
</table>

#### alpine.database.url

Specifies the JDBC URL to use when connecting to the database.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">Yes</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">jdbc:h2:~/.dependency-track/db;DB_CLOSE_ON_EXIT=FALSE</td>
    </tr>
    <tr>
      <th style="text-align: right">Example</th>
      <td style="border-width: 0">jdbc:postgresql://localhost:5432/dtrack</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_URL</td>
    </tr>
  </tbody>
</table>

#### alpine.database.username

Specifies the username to use when authenticating to the database.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">sa</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATABASE_USERNAME</td>
    </tr>
  </tbody>
</table>

#### alpine.datanucleus.cache.level2.type

Controls the 2nd level cache type used by DataNucleus, the Object Relational Mapper (ORM).
See <https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#cache_level2>.
Setting this property to "none" may help in reducing the memory footprint of Dependency-Track,
but has the potential to slow down database operations.
Size of the cache may be monitored through the "datanucleus_cache_second_level_entries" metric,
refer to <https://docs.dependencytrack.org/getting-started/monitoring/#metrics> for details.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">enum</td>
    </tr>
    <tr>
      <th style="text-align: right">Valid Values</th>
      <td style="border-width: 0">[soft, weak, none]</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">soft</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATANUCLEUS_CACHE_LEVEL2_TYPE</td>
    </tr>
  </tbody>
</table>



### General

#### alpine.api.key.prefix

Defines the prefix to be used for API keys. A maximum prefix length of 251
characters is supported. The prefix may also be left empty.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">odt_</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_API_KEY_PREFIX</td>
    </tr>
  </tbody>
</table>

#### alpine.bcrypt.rounds

Specifies the number of bcrypt rounds to use when hashing a user's password.
The higher the number the more secure the password, at the expense of
hardware resources and additional time to generate the hash.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">Yes</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">14</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_BCRYPT_ROUNDS</td>
    </tr>
  </tbody>
</table>

#### alpine.data.directory

Defines the path to the data directory. This directory will hold logs,
keys, and any database or index files along with application-specific
files or directories.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">Yes</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">~/.dependency-track</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_DATA_DIRECTORY</td>
    </tr>
  </tbody>
</table>

#### alpine.private.key.path

Defines the path to the private key of the public-private key pair.
The key will be generated upon first startup if it does not exist.
The key pair is currently not used by Dependency-Track.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">${alpine.data.directory}/keys/private.key</td>
    </tr>
    <tr>
      <th style="text-align: right">Example</th>
      <td style="border-width: 0">/var/run/secrets/private.key</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_PRIVATE_KEY_PATH</td>
    </tr>
  </tbody>
</table>

#### alpine.public.key.path

Defines the path to the public key of the public-private key pair.
The key will be generated upon first startup if it does not exist.
The key pair is currently not used by Dependency-Track.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">${alpine.data.directory}/keys/public.key</td>
    </tr>
    <tr>
      <th style="text-align: right">Example</th>
      <td style="border-width: 0">/var/run/secrets/public.key</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_PUBLIC_KEY_PATH</td>
    </tr>
  </tbody>
</table>

#### alpine.secret.key.path

Defines the path to the secret key to be used for data encryption and decryption.
The key will be generated upon first startup if it does not exist.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">${alpine.data.directory}/keys/secret.key</td>
    </tr>
    <tr>
      <th style="text-align: right">Example</th>
      <td style="border-width: 0">/var/run/secrets/secret.key</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_SECRET_KEY_PATH</td>
    </tr>
  </tbody>
</table>

#### system.requirement.check.enabled

Define whether system requirement check is enabled.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">true</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">SYSTEM_REQUIREMENT_CHECK_ENABLED</td>
    </tr>
  </tbody>
</table>



### HTTP

#### alpine.http.proxy.address

HTTP proxy address. If set, then [`alpine.http.proxy.port`](#alpinehttpproxyport) must be set too.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">Example</th>
      <td style="border-width: 0">proxy.example.com</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_HTTP_PROXY_ADDRESS</td>
    </tr>
  </tbody>
</table>

#### alpine.http.proxy.password



<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_HTTP_PROXY_PASSWORD</td>
    </tr>
  </tbody>
</table>

#### alpine.http.proxy.port



<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">Example</th>
      <td style="border-width: 0">8888</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_HTTP_PROXY_PORT</td>
    </tr>
  </tbody>
</table>

#### alpine.http.proxy.username



<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_HTTP_PROXY_USERNAME</td>
    </tr>
  </tbody>
</table>

#### alpine.http.timeout.connection

Defines the connection timeout in seconds for outbound HTTP connections.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">30</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_HTTP_TIMEOUT_CONNECTION</td>
    </tr>
  </tbody>
</table>

#### alpine.http.timeout.pool

Defines the request timeout in seconds for outbound HTTP connections.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">60</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_HTTP_TIMEOUT_POOL</td>
    </tr>
  </tbody>
</table>

#### alpine.http.timeout.socket

Defines the socket / read timeout in seconds for outbound HTTP connections.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">30</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_HTTP_TIMEOUT_SOCKET</td>
    </tr>
  </tbody>
</table>

#### alpine.no.proxy



<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">Example</th>
      <td style="border-width: 0">localhost,127.0.0.1</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_NO_PROXY</td>
    </tr>
  </tbody>
</table>



### LDAP

#### alpine.ldap.attribute.mail

Specifies the LDAP attribute used to store a users email address


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">mail</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_ATTRIBUTE_MAIL</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.attribute.name

Specifies the Attribute that identifies a users ID.
<br/><br/>
Example (Microsoft Active Directory):
<ul><li><code>userPrincipalName</code></li></ul>
Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
<ul><li><code>uid</code></li></ul>


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">userPrincipalName</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_ATTRIBUTE_NAME</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.auth.username.format

Specifies if the username entered during login needs to be formatted prior
to asserting credentials against the directory. For Active Directory, the
userPrincipal attribute typically ends with the domain, whereas the
samAccountName attribute and other directory server implementations do not.
The %s variable will be substituted with the username asserted during login.
<br/><br/>
Example (Microsoft Active Directory):
<ul><li><code>%s@example.com</code></li></ul>
Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
<ul><li><code>%s</code></li></ul>


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">%s@example.com</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_AUTH_USERNAME_FORMAT</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.basedn

Specifies the base DN that all queries should search from


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">dc=example,dc=com</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_BASEDN</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.bind.password

If anonymous access is not permitted, specify a password for the username
used to bind.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_BIND_PASSWORD</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.bind.username

If anonymous access is not permitted, specify a username with limited access
to the directory, just enough to perform searches. This should be the fully
qualified DN of the user.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_BIND_USERNAME</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.enabled

Defines if LDAP will be used for user authentication. If enabled,
`alpine.ldap.*` properties should be set accordingly.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">false</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_ENABLED</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.groups.filter

Specifies the LDAP search filter used to retrieve all groups from the directory.
<br/><br/>
Example (Microsoft Active Directory):
<ul><li><code>(&(objectClass=group)(objectCategory=Group))</code></li></ul>
Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
<ul><li><code>(&(objectClass=groupOfUniqueNames))</code></li></ul>


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">(&(objectClass=group)(objectCategory=Group))</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_GROUPS_FILTER</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.groups.search.filter

Specifies the LDAP search filter used to search for groups by their name.
The `{SEARCH_TERM}` variable will be substituted at runtime.
<br/><br/>
Example (Microsoft Active Directory):
<ul><li><code>(&(objectClass=group)(objectCategory=Group)(cn=*{SEARCH_TERM}*))</code></li></ul>
Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
<ul><li><code>(&(objectClass=groupOfUniqueNames)(cn=*{SEARCH_TERM}*))</code></li></ul>


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">(&(objectClass=group)(objectCategory=Group)(cn=*{SEARCH_TERM}*))</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_GROUPS_SEARCH_FILTER</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.security.auth

Specifies the LDAP security authentication level to use.
If this property is empty or unspecified, the behaviour is determined by the service provider.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">enum</td>
    </tr>
    <tr>
      <th style="text-align: right">Valid Values</th>
      <td style="border-width: 0">[none, simple, strong]</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">simple</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_SECURITY_AUTH</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.server.url

Specifies the LDAP server URL.
<br/><br/>
Examples (Microsoft Active Directory):
<ul>
<li><code>ldap://ldap.example.com:3268</code></li>
<li><code>ldaps://ldap.example.com:3269</code></li>
</ul>
Examples (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
<ul>
<li><code>ldap://ldap.example.com:389</code></li>
<li><code>ldaps://ldap.example.com:636</code></li>
</ul>


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">ldap://ldap.example.com:389</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_SERVER_URL</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.team.synchronization

This option will ensure that team memberships for LDAP users are dynamic and
synchronized with membership of LDAP groups. When a team is mapped to an LDAP
group, all local LDAP users will automatically be assigned to the team if
they are a member of the group the team is mapped to. If the user is later
removed from the LDAP group, they will also be removed from the team. This
option provides the ability to dynamically control user permissions via an
external directory.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">false</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_TEAM_SYNCHRONIZATION</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.user.groups.filter

Specifies the LDAP search filter to use to query a user and retrieve a list
of groups the user is a member of. The `{USER_DN}` variable will be substituted
with the actual value of the users DN at runtime.
<br/><br/>
Example (Microsoft Active Directory):
<ul><li><code>(&(objectClass=group)(objectCategory=Group)(member={USER_DN}))</code></li></ul>
Example (Microsoft Active Directory - with nested group support):
<ul><li><code>(member:1.2.840.113556.1.4.1941:={USER_DN})</code></li></ul>
Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
<ul><li><code>(&(objectClass=groupOfUniqueNames)(uniqueMember={USER_DN}))</code></li></ul>


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">(member:1.2.840.113556.1.4.1941:={USER_DN})</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_USER_GROUPS_FILTER</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.user.provisioning

Specifies if mapped LDAP accounts are automatically created upon successful
authentication. When a user logs in with valid credentials but an account has
not been previously provisioned, an authentication failure will be returned.
This allows admins to control specifically which ldap users can access the
system and which users cannot. When this value is set to true, a local ldap
user will be created and mapped to the ldap account automatically. This
automatic provisioning only affects authentication, not authorization.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">false</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_USER_PROVISIONING</td>
    </tr>
  </tbody>
</table>

#### alpine.ldap.users.search.filter

Specifies the LDAP search filter used to search for users by their name.
The <code>{SEARCH_TERM}</code> variable will be substituted at runtime.
<br/><br/>
Example (Microsoft Active Directory):
<ul><li><code>(&(objectClass=group)(objectCategory=Group)(cn=*{SEARCH_TERM}*))</code></li></ul>
Example (ApacheDS, Fedora 389 Directory, NetIQ/Novell eDirectory, etc):
<ul><li><code>(&(objectClass=inetOrgPerson)(cn=*{SEARCH_TERM}*))</code></li></ul>


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">(&(objectClass=user)(objectCategory=Person)(cn=*{SEARCH_TERM}*))</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_LDAP_USERS_SEARCH_FILTER</td>
    </tr>
  </tbody>
</table>



### Observability

#### alpine.metrics.auth.password

Defines the password required to access metrics.
Has no effect when [`alpine.metrics.auth.username`](#alpinemetricsauthusername) is not set.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_METRICS_AUTH_PASSWORD</td>
    </tr>
  </tbody>
</table>

#### alpine.metrics.auth.username

Defines the username required to access metrics.
Has no effect when [`alpine.metrics.auth.password`](#alpinemetricsauthpassword) is not set.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_METRICS_AUTH_USERNAME</td>
    </tr>
  </tbody>
</table>

#### alpine.metrics.enabled

Defines whether Prometheus metrics will be exposed.
If enabled, metrics will be available via the /metrics endpoint.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">false</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_METRICS_ENABLED</td>
    </tr>
  </tbody>
</table>



### OpenID Connect

#### alpine.oidc.client.id

Defines the client ID to be used for OpenID Connect.
The client ID should be the same as the one configured for the frontend,
and will only be used to validate ID tokens.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_OIDC_CLIENT_ID</td>
    </tr>
  </tbody>
</table>

#### alpine.oidc.enabled

Defines if OpenID Connect will be used for user authentication.
If enabled, `alpine.oidc.*` properties should be set accordingly.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">false</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_OIDC_ENABLED</td>
    </tr>
  </tbody>
</table>

#### alpine.oidc.issuer

Defines the issuer URL to be used for OpenID Connect.
This issuer MUST support provider configuration via the `/.well-known/openid-configuration` endpoint.
See also:
<ul>
<li>https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata</li>
<li>https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig</li>
</ul>


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_OIDC_ISSUER</td>
    </tr>
  </tbody>
</table>

#### alpine.oidc.team.synchronization

This option will ensure that team memberships for OpenID Connect users are dynamic and
synchronized with membership of OpenID Connect groups or assigned roles. When a team is
mapped to an OpenID Connect group, all local OpenID Connect users will automatically be
assigned to the team if they are a member of the group the team is mapped to. If the user
is later removed from the OpenID Connect group, they will also be removed from the team. This
option provides the ability to dynamically control user permissions via the identity provider.
Note that team synchronization is only performed during user provisioning and after successful
authentication.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">false</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_OIDC_TEAM_SYNCHRONIZATION</td>
    </tr>
  </tbody>
</table>

#### alpine.oidc.teams.claim

Defines the name of the claim that contains group memberships or role assignments in the provider's userinfo endpoint.
The claim must be an array of strings. Most public identity providers do not support group or role management.
When using a customizable / on-demand hosted identity provider, name, content, and inclusion in the userinfo endpoint
will most likely need to be configured.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">groups</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_OIDC_TEAMS_CLAIM</td>
    </tr>
  </tbody>
</table>

#### alpine.oidc.teams.default

Defines one or more team names that auto-provisioned OIDC users shall be added to.
Multiple team names may be provided as comma-separated list.
Has no effect when [`alpine.oidc.user.provisioning`](#alpineoidcuserprovisioning) is false, or [`alpine.oidc.team.synchronization`](#alpineoidcteamsynchronization) is true.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">null</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_OIDC_TEAMS_DEFAULT</td>
    </tr>
  </tbody>
</table>

#### alpine.oidc.user.provisioning

Specifies if mapped OpenID Connect accounts are automatically created upon successful
authentication. When a user logs in with a valid access token but an account has
not been previously provisioned, an authentication failure will be returned.
This allows admins to control specifically which OpenID Connect users can access the
system and which users cannot. When this value is set to true, a local OpenID Connect
user will be created and mapped to the OpenID Connect account automatically. This
automatic provisioning only affects authentication, not authorization.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">boolean</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">false</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_OIDC_USER_PROVISIONING</td>
    </tr>
  </tbody>
</table>

#### alpine.oidc.username.claim

Defines the name of the claim that contains the username in the provider's userinfo endpoint.
Common claims are `name`, `username`, `preferred_username` or `nickname`.
See also:
<ul>
<li>https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse</li>
</ul>


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">string</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">name</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_OIDC_USERNAME_CLAIM</td>
    </tr>
  </tbody>
</table>



### Other

#### alpine.worker.pool.drain.timeout.duration

Required
Defines the maximum duration for which Dependency-Track will wait for queued
events and notifications to be processed when shutting down.
During shutdown, newly dispatched events will not be accepted.
The duration must be specified in ISO 8601 notation (https://en.wikipedia.org/wiki/ISO_8601#Durations).


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">No</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0"></td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">PT5S</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_WORKER_POOL_DRAIN_TIMEOUT_DURATION</td>
    </tr>
  </tbody>
</table>



### Task Execution

#### alpine.worker.thread.multiplier

Defines a multiplier that is used to calculate the number of threads used
by the event subsystem. This property is only used when [`alpine.worker.threads`](#alpineworkerthreads)
is set to 0. A machine with 4 cores and a multiplier of 4, will use (at most)
16 worker threads.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">Yes</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">4</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_WORKER_THREAD_MULTIPLIER</td>
    </tr>
  </tbody>
</table>

#### alpine.worker.threads

Defines the number of worker threads that the event subsystem will consume.
Events occur asynchronously and are processed by the Event subsystem. This
value should be large enough to handle most production situations without
introducing much delay, yet small enough not to pose additional load on an
already resource-constrained server.
A value of 0 will instruct Alpine to allocate 1 thread per CPU core. This
can further be tweaked using the [`alpine.worker.thread.multiplier`](#alpineworkerthreadmultiplier) property.


<table>
  <tbody style="border: 0">
    <tr>
      <th style="text-align: right">Required</th>
      <td style="border-width: 0">Yes</td>
    </tr>
    <tr>
      <th style="text-align: right">Type</th>
      <td style="border-width: 0">integer</td>
    </tr>
    <tr>
      <th style="text-align: right">Default</th>
      <td style="border-width: 0">0</td>
    </tr>
    <tr>
      <th style="text-align: right">ENV</th>
      <td style="border-width: 0">ALPINE_WORKER_THREADS</td>
    </tr>
  </tbody>
</table>


