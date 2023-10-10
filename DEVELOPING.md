# Hacking on OWASP Dependency-Track

Want to hack on Dependency-Track? Awesome, here's what you need to know to get started!

> Please be sure to read [`CONTRIBUTING.md`](./CONTRIBUTING.md) and 
> [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) as well.

## Repositories

As of now, the Dependency-Track project consists of two separate repositories:

* [DependencyTrack/dependency-track](https://github.com/DependencyTrack/dependency-track) - The main application, also referred to as API server, based on Java and [Alpine](https://github.com/stevespringett/Alpine).
* [DependencyTrack/frontend](https://github.com/DependencyTrack/frontend) - The frontend, a single page application (SPA), based on JavaScript and [Vue](https://vuejs.org/).

This document primarily covers the API server. Please refer to the frontend repository for frontend-specific instructions.

## Prerequisites

There are a few things you'll need on your journey:

* JDK 17+ ([Temurin](https://adoptium.net/temurin/releases) distribution recommended)
* Maven (comes bundled with IntelliJ and Eclipse)
* A Java IDE of your preference (we recommend IntelliJ, but any other IDE is fine as well)
* Docker (optional)

> We provide common [run configurations](https://www.jetbrains.com/help/idea/run-debug-configuration.html) for IntelliJ 
> in the [`.idea/runConfigurations`](./.idea/runConfigurations) directory for convenience. IntelliJ will automatically pick those up when you open this repository.

## Core Technologies

Knowing about the core technologies used by the API server may help you with understanding its codebase.

| Technology                                                                                      | Purpose                   |
|:------------------------------------------------------------------------------------------------|:--------------------------|
| [JAX-RS](https://projects.eclipse.org/projects/ee4j.rest)                                       | REST API specification    |
| [Jersey](https://eclipse-ee4j.github.io/jersey/)                                                | JAX-RS implementation     |
| [Java Data Objects (JDO)](https://db.apache.org/jdo/)                                           | Persistence specification |
| [DataNucleus](https://www.datanucleus.org/products/accessplatform/jdo/getting_started.html)     | JDO implementation        |
| [Jetty](https://www.eclipse.org/jetty/)                                                         | Servlet Container         |
| [Alpine](https://github.com/stevespringett/Alpine)                                              | Framework / Scaffolding   |

## Building

Build an executable JAR containing just the API server:

```shell
mvn clean package -P clean-exclude-wars -P enhance -P embedded-jetty -DskipTests -Dlogback.configuration.file=src/main/docker/logback.xml
```

Build an executable JAR that contains both API server and frontend (aka "bundled" distribution):

```shell
mvn clean package -P clean-exclude-wars -P enhance -P embedded-jetty -P bundle-ui -DskipTests -Dlogback.configuration.file=src/main/docker/logback.xml
```

> When using the `bundle-ui` profile, Maven will download a [`DependencyTrack/frontend`](https://github.com/DependencyTrack/frontend) 
> release and include it in the JAR. The frontend version is specified via the `frontend.version` property in [`pom.xml`](./pom.xml).

The resulting files are placed in `./target` as `dependency-track-apiserver.jar` or `dependency-track-bundled.jar` respectively.
Both JARs ship with an [embedded Jetty server](https://github.com/stevespringett/Alpine/tree/master/alpine-executable-war), 
there's no need to deploy them in an application server like Tomcat or WildFly.

## Running

To run a previously built executable JAR, just invoke it with `java -jar`, e.g.:

```shell
java -jar ./target/dependency-track-apiserver.jar
```

The API server will be available at `http://127.0.0.1:8080`.

Additional configuration (e.g. database connection details) can be provided as usual via `application.properties`
or environment variables. Refer to the [configuration documentation](https://docs.dependencytrack.org/getting-started/configuration/).

## Debugging

To build and run the API server in one go, invoke the Jetty Maven plugin as follows:

```shell
mvn jetty:run -P enhance -Dlogback.configurationFile=src/main/docker/logback.xml
```

> Note that the `bundle-ui` profile has no effect using this method. 
> It works only for the API server, not the bundled distribution.

The above command is also suitable for debugging. For IntelliJ, simply *Debug* the [Jetty](./.idea/runConfigurations/Jetty.run.xml) run configuration.

### Inspecting the database

Unless configured otherwise, Dependency-Track will use an [H2](https://www.h2database.com/html/main.html) database in 
`embedded` mode. The database file is located at `~/.dependency-track/db.mv.db`.

You can open and inspect the database file, for example with tools like [DBeaver](https://dbeaver.io/) or 
[IntelliJ Ultimate's integrated one](https://www.jetbrains.com/help/idea/database-tool-window.html),
using the following connection details:

* JDBC URL: `jdbc:h2:~/.dependency-track/db`
* Username: `sa`
* Password: none

These are the values defined via `alpine.database.*` properties in the
[`application.properties`](src/main/resources/application.properties) file.

> **Warning**  
> Make sure that your database tool uses version **2** of the H2 database driver.
> Connections using version 1 of the driver will fail!

A limitation of the H2 database in `embedded` mode is that *only a single process at a time can access it*.
If you want to inspect the database while Dependency-Track is running, you have two options:

#### Enable the embedded H2 console

When building Dependency-Track locally, you can opt in to enabling an embedded 
[H2 console](http://www.h2database.com/html/quickstart.html#h2_console). 

To enable it, simply pass the additional `h2-console` Maven profile to your build command.
This also works with the Jetty Maven plugin:

```shell
mvn jetty:run -P enhance -P h2-console -Dlogback.configurationFile=src/main/docker/logback.xml
```

Once enabled, the console will be available at http://localhost:8080/h2-console.

> **Note**  
> Supporting the H2 console via a dedicated build profile instead of a runtime configuration 
> was an [active decision](https://github.com/DependencyTrack/dependency-track/pull/2592). Exposing
> the console is a security risk, and should only ever be done for local testing purposes. Enabling
> the console is not possible in official builds distributed via GitHub releases and Docker Hub.

#### Use an external database

Simply set up any of the [supported external databases](https://docs.dependencytrack.org/getting-started/database-support/).
Docker makes this very easy. Here's an example for how you can do it with PostgreSQL:

```shell
# Launch a Postgres container
docker run -d --name postgres -p "127.0.0.1:5432:5432" \
  -e "POSTGRES_DB=dtrack" -e "POSTGRES_USER=dtrack" -e "POSTGRES_PASSWORD=dtrack" \
  postgres:15-alpine

# Configure the database connection for Dependency-Track
export ALPINE_DATABASE_MODE=external
export ALPINE_DATABASE_URL=jdbc:postgresql://localhost:5432/dtrack
export ALPINE_DATABASE_DRIVER=org.postgresql.Driver
export ALPINE_DATABASE_USERNAME=dtrack
export ALPINE_DATABASE_PASSWORD=dtrack

# Launch Dependency-Track
mvn jetty:run -P enhance -Dlogback.configurationFile=src/main/docker/logback.xml
```

You can now use tooling native to your chosen RDBMS, for example [pgAdmin](https://www.pgadmin.org/).

### Skipping NVD mirroring

For local debugging and testing, it is sometimes desirable to skip the NVD mirroring process
that is executed a minute after Dependency-Track has started.

This can be achieved by tricking Dependency-Track into thinking that it already
mirrored the NVD data, so there's no need to re-download it again.

Prior to starting Dependency-Track, execute the `data-nist-generate-dummy.sh` script:

```shell
./dev/scripts/data-nist-generate-dummy.sh
```

> **Note** 
> The `modified` feed will still be downloaded. But that feed is so small that it
> doesn't really have an impact.

When testing containerized deployments, simply mount the local directory containing the prepared
NVD data into the container:

```shell
./dev/scripts/data-nist-generate-dummy.sh
docker run -d --name dtrack \
  -v "$HOME/.dependency-track:/data/.dependency-track" \
  -p '127.0.0.1:8080:8080' dependencytrack/apiserver:snapshot
```

## Debugging with Frontend

Start the API server via the Jetty Maven plugin (see [Debugging](#debugging) above). The API server will listen on 
`http://127.0.0.1:8080`.

Clone the frontend repository, install its required dependencies and launch the Vue development server:

```shell
git clone https://github.com/DependencyTrack/frontend.git dependency-track-frontend
cd ./dependency-track-frontend
npm ci
npm run serve
```

Per default, the Vue development server will listen on port `8080`. If that port is taken, it will choose a higher,
unused port (typically `8081`). Due to this behavior, it is important to always start the API server first, unless
you want to fiddle with default configurations of both API server and frontend.

Now visit `http://127.0.0.1:8081` in your browser and use Dependency-Track as usual.

## Testing

### Running unit tests

To run all tests:

```shell
mvn clean verify -P enhance
```

Depending on your machine, this will take roughly 10-30min. Unless you modified central parts of the application,
starting single tests separately via IDE is a better choice. 

### Testing manually

We provide multiple Docker Compose files that can be used to quickly set up a local testing environment.  
The files are located in the [`dev`](dev/) directory.

#### With embedded H2 database

The default [`docker-compose.yml`](dev/docker-compose.yml) will deploy a frontend and API server container using an 
embedded H2 database.

```shell
cd dev
docker compose up -d
```

#### With PostgreSQL database

To use a PostgreSQL database instead of embedded H2, use [`docker-compose.postgres.yml`](dev/docker-compose.postgres.yml).

```shell
cd dev
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d
```

#### With Microsoft SQL Server database

To use a Microsoft SQL Server database instead of embedded H2, use [`docker-compose.mssql.yml`](dev/docker-compose.mssql.yml).

```shell
cd dev
docker compose -f docker-compose.yml -f docker-compose.mssql.yml up -d
```

#### With monitoring stack

To deploy both Prometheus and Grafana, [`docker-compose.monitoring.yml`](dev/docker-compose.monitoring.yml) may be supplied to any
of the commands listed above. For example:

```shell
cd dev
docker compose -f docker-compose.yml -f docker-compose.postgres.yml -f docker-compose.monitoring.yml up -d
```

Prometheus will automatically discover the API server's metrics. Grafana is configured to provision Prometheus
as datasource, and import the [sample dashboard](https://docs.dependencytrack.org/getting-started/monitoring/#grafana-dashboard)
on startup.

To view the dashboard, visit http://localhost:3000 in your browser. The initial Grafana credentials are:

* Username: `admin`
* Password: `admin`

## DataNucleus Bytecode Enhancement

Occasionally when running tests without Maven from within your IDE, you will run into failures due to exceptions
similar to this one:

```
org.datanucleus.exceptions.NucleusUserException: Found Meta-Data for class org.dependencytrack.model.Component but this class is either not enhanced or you have multiple copies of the persistence API jar in your CLASSPATH!! Make sure all persistable classes are enhanced before running DataNucleus and/or the CLASSPATH is correct.
```

This happens because DataNucleus requires classes annotated with `@PersistenceCapable` to be [enhanced](https://www.datanucleus.org/products/accessplatform/jdo/enhancer.html).
Enhancement is performed on compiled bytecode and thus has to be performed post-compilation 
(`process-classes` [lifecycle phase](https://maven.apache.org/guides/introduction/introduction-to-the-lifecycle.html#Lifecycle_Reference) in Maven). 
During a Maven build, the [DataNucleus Maven plugin](https://www.datanucleus.org/products/accessplatform/jdo/enhancer.html#maven)
takes care of this (that's also why `-P enhance` is required in all Maven commands).

Because most IDEs run their own build when executing tests, effectively bypassing Maven, bytecode enhancement is not
performed, and exceptions as that shown above are raised. If this happens, you can manually kick off the bytecode
enhancement like this:

```shell
mvn clean process-classes -P enhance
```

Now just execute the test again, and it should just work. 

> If you're still running into issues, ensure that your IDE is not cleaning the workspace 
> (removing the `target` directory) before executing the test. 

## Building Container Images

Ensure you've built either API server or the bundled distribution, or both.

To build the API server image:

```shell
docker build --build-arg WAR_FILENAME=dependency-track-apiserver.jar -t dependencytrack/apiserver:local -f ./src/main/docker/Dockerfile .
```

To build the bundled image:

```shell
docker build --build-arg WAR_FILENAME=dependency-track-bundled.jar -t dependencytrack/bundled:local -f ./src/main/docker/Dockerfile .
```

## Documentation

The documentation is built using [Jekyll](https://jekyllrb.com/) and published to 
[docs.dependencytrack.org](https://docs.dependencytrack.org). Sources are located in the [`docs`](./docs) directory.

There is a lot going on in `docs`, but most of the time you'll want to spend your time in these directories:

* [`docs/_docs`](./docs/_docs): The *actual* documentation
* [`docs/_posts`](./docs/_posts): The changelogs

To build the docs, run:

```shell
./dev/scripts/docs-build.sh
```

This installs all required dependencies (among them Jekyll) to `docs/vendor/bundle`, generates the documentation
website and stores it in `docs/_site`.

For local development, you may want to run this instead: 
```shell
./dev/scripts/docs-dev.sh
```

This will start a local webserver that listens on `127.0.0.1:4000` and rebuilds the site whenever you make changes.

> To be able to build the docs with Jekyll, you'll need [Ruby 2](https://www.ruby-lang.org/en/),
> [RubyGems](https://rubygems.org/pages/download) and [Bundler](https://bundler.io/) installed.
> If you can't be bothered to install all of this, you can use the 
> [Jekyll container image](https://hub.docker.com/r/jekyll/jekyll) instead, e.g.:
> ```
> docker run --rm -it --name jekyll -p "127.0.0.1:4000:4000" -v "$(pwd)/docs:/srv/jekyll:Z" jekyll/jekyll:3.8 jekyll serve
> ```
