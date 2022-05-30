# Hacking on OWASP Dependency-Track

Want to hack on Dependency-Track? Awesome, here's what you need to know to get started!

> Please be sure to read [`CONTRIBUTING.md`](./CONTRIBUTING.md) and 
> [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) as well.

## Repositories

As of now, the Dependency-Track project consists of two separate repositories:

* [DependencyTrack/dependency-track](https://github.com/DependencyTrack/dependency-track)
* [DependencyTrack/frontend](https://github.com/DependencyTrack/frontend)

TODO: Quick description of what each repo consists of and what their purpose is.

## Prerequisites

There are a few things you'll need on your journey:

* JDK 11 ([Temurin](https://adoptium.net/temurin/releases) distribution recommended)
* Maven (comes bundled with IntelliJ and Eclipse)
* Docker (optional, but very useful)
* A Java IDE of your preference

> We provide common run configurations for IntelliJ in the [`.run`](./.run) directory. 
> IntelliJ will automatically pick those up when you open this repository. 

## Core Technologies

| Technology                                                                                  | Purpose                   |
|:--------------------------------------------------------------------------------------------|:--------------------------|
| [JAX-RS](https://projects.eclipse.org/projects/ee4j.rest)                                   | REST API specification    |
| [Jersey](https://eclipse-ee4j.github.io/jersey/)                                            | JAX-RS implementation     |
| [Java Data Objects](https://db.apache.org/jdo/) (JDO)                                       | Persistence specification |
| [DataNucleus](https://www.datanucleus.org/products/accessplatform/jdo/getting_started.html) | JDO implementation        |
| [Jetty](https://www.eclipse.org/jetty/)                                                     | Servlet Container         |
| [Alpine](https://github.com/stevespringett/Alpine)                                          | Framework / Scaffolding   |

## Architecture

TODO: Broad overview of the API server architecture

## Building

Build an executable JAR containing just the API server:

```shell
mvn clean package -P enhance -P embedded-jetty -DskipTests -Dlogback.configuration.file=src/main/docker/logback.xml
```

Build an executable JAR that contains both API server and frontend (aka "bundled" distribution):

```shell
mvn clean package -P enhance -P embedded-jetty -P bundle-ui -DskipTests -Dlogback.configuration.file=src/main/docker/logback.xml
```

> When using the `bundle-ui` profile, Maven will download a DependencyTrack/frontend release and include it in the JAR.
> The frontend version is specified via the `frontend.version` property in [`pom.xml`](./pom.xml).

The resulting files are placed in `target` as `dependency-track-apiserver.jar` or `dependency-track-bundled.jar` respectively.
Both JARs ship with an embedded Jetty server, there's no need to deploy them in an application server like Tomcat or Wildfly.

To run them, just invoke them with `java -jar`, e.g.:

```shell
java -jar ./target/dependency-track-apiserver.jar
```

## Debugging

To build and run the API server in one go, invoke the Jetty Maven plugin as follows:

```shell
mvn jetty:run -P enhance -Dlogback.configurationFile=src/main/docker/logback.xml
```

> The `bundle-ui` profile has no effect using this method. 
> It works only for the API server, not the bundled distribution.

The above command is also suitable for debugging. For IntelliJ, simply *Debug* the [Jetty](./.run/Jetty.run.xml) run configuration.

> While the Jetty Maven plugin supports automatic reloading, we disabled it by default. 
> It doesn't play well with Dependency-Track for the time being.

## Testing

To run all tests:

```shell
mvn clean verify
```

Depending on your machine, this will take roughly 10-40min. Unless you modified central parts of the application,
starting single tests separately via IDE is a better choice. 

## Documentation

The documentation is built using [Jekyll](https://jekyllrb.com/) and published to 
[docs.dependencytrack.org](https://docs.dependecytrack.org). Sources are located in the [`docs`](./docs) directory.

There is a lot going on in `docs`, but most of the time you'll want to spend your time in these directories:

* [`docs/_docs`](./docs/_docs): The *actual* documentation
* [`docs/_posts`](./docs/_posts): The changelogs

To build the docs, run:

```shell
./scripts/docs-build.sh
```

This installs all required dependencies (among them Jekyll) to `docs/vendor/bundle`, generates the documentation
website and stores it in `docs/_site`. You can view the site by opening `docs/_site/index.html` in a browser.

For local development, you may want to run this instead: 
```shell
./scripts/docs-dev.sh
```

instead. This will start a local webserver that listens on `127.0.0.1:4000` and rebuilds the site whenever you change the sources.