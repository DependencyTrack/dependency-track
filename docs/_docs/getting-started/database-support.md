---
title: Database Support
category: Getting Started
chapter: 1
order: 6
---

Dependency-Track includes an embedded H2 database enabled by default. The intended purpose of this 
database is for quick evaluation, testing, and demonstration of the platform and its capabilities. 

> The embedded H2 database is not intended for production use!

Dependency-Track supports the following database servers:

| RDBMS                | Supported Versions | Recommended |
|:---------------------|:-------------------|:------------|
| PostgreSQL           | >= 9.0             | ✅           |
| Microsoft SQL Server | >= 2012            | ✅           |
| MySQL                | 5.6 - 5.7          | ❌           |

Dependency-Track requires extensive unicode support, which is not provided per default in MySQL.
Both PostgreSQL and SQL Server have been proven to work very well in production deployments, while
MySQL / MariaDB can require [lots of extra care](https://github.com/DependencyTrack/dependency-track/issues/271#issuecomment-1108923693). 
**Only use MySQL if you know what you're doing**!

Refer to the [Configuration] documentation for how database settings may be changed.

### Examples

#### PostgreSQL

```ini
alpine.database.mode=external
alpine.database.url=jdbc:postgresql://localhost:5432/dtrack
alpine.database.driver=org.postgresql.Driver
alpine.database.username=dtrack
alpine.database.password=password
```

#### Microsoft SQL Server

```ini
alpine.database.mode=external
alpine.database.url=jdbc:sqlserver://localhost:1433;databaseName=dtrack;sendStringParametersAsUnicode=false
alpine.database.driver=com.microsoft.sqlserver.jdbc.SQLServerDriver
alpine.database.username=dtrack
alpine.database.password=password
```

#### MySQL

```ini
alpine.database.mode=external
alpine.database.url=jdbc:mysql://localhost:3306/dtrack?autoReconnect=true&useSSL=false
alpine.database.driver=com.mysql.cj.jdbc.Driver
alpine.database.username=dtrack
alpine.database.password=password
```

It is necessary to configure the [SQL mode] such that it *does not* include `NO_ZERO_IN_DATE` and `NO_ZERO_DATE`,
but *does* include `ANSI_QUOTES`. There are several ways to change this configuration, however the recommended way is 
to modify the  MySQL configuration file (typically `my.ini` or similar) with the following:

```ini
[mysqld] 
sql_mode="ANSI_QUOTES,STRICT_TRANS_TABLES,ONLY_FULL_GROUP_BY,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
```

Alternatively, when the database is shared with other applications, session variables in the JDBC URL can be used:

```ini
alpine.database.url=jdbc:mysql://localhost:3306/dtrack?autoReconnect=true&useSSL=false&sessionVariables=sql_mode='ANSI_QUOTES,STRICT_TRANS_TABLES,ONLY_FULL_GROUP_BY,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION'
```

MySQL may erroneously report index key length violations ("Specified key was too long"), when in fact the multi-byte
key length is lower than the actual value. **Do not use MySQL if don't know how to work around errors like this**!

#### Cloud SQL

Connecting to Cloud SQL with IAM and mTLS is supported using the Cloud SQL database connectors included.

More information [here](https://github.com/GoogleCloudPlatform/cloud-sql-jdbc-socket-factory)

##### CloudSQL PostgreSQL

```
jdbc:postgresql:///<DATABASE_NAME>?cloudSqlInstance=<INSTANCE_CONNECTION_NAME>&socketFactory=com.google.cloud.sql.postgres.SocketFactory
```

##### CloudSQL Microsoft SQL Server

```
jdbc:sqlserver://localhost;databaseName=<DATABASE_NAME>;socketFactoryClass=com.google.cloud.sql.sqlserver.SocketFactory;socketFactoryConstructorArg=<INSTANCE_CONNECTION_NAME>
```

##### CloudSQL MySQL

```
jdbc:mysql:///<DATABASE_NAME>?cloudSqlInstance=<INSTANCE_CONNECTION_NAME>&socketFactory=com.google.cloud.sql.mysql.SocketFactory
```

### Connection Pooling

The Dependency-Track API server utilizes **two** database connection pools - one for *transactional* and one for 
*non-transactional* operations. Roughly speaking, writing operations will make use of the transactional connection pool,
while read-only operations will use the non-transactional pool. Under normal circumstances, Dependency-Track performs
way more read-only than write operations. Per default, both pools are configured with a maximum size of 20 connections, 
and a minimum amount of 10 idle connections. This may be adjusted via the `alpine.database.pool.*` properties,
see [Configuration].

As connection pool sizing highly depends on the deployment at hand, it is not possible to give general recommendations
as to how big or small the pools should be. When in doubt, the default configuration should work for the majority of users.
If customization of connection pool sizes is desired, it is recommended to read the [About Pool Sizing] article,
published by the creator of [HikariCP], the connection pool implementation used by Dependency-Track.

Additionally, meetrics about both connection pools are exposed via Prometheus, and it is strongly recommended to 
monitor them (see [Monitoring]) before making any changes to the default configuration.

![Connection Pool Metrics]({{ site.baseurl }}/images/screenshots/database-connection-pool-metrics.png)

### Migrating to H2 v2

With Dependency-Track 4.6.0, the embedded H2 database has been upgraded to version 2.
As stated in the official [Migration to 2.0](https://www.h2database.com/html/migration-to-v2.html) guide,
databases created by H2 v1 are incompatible with H2 v2. As a consequence, Dependency-Track 4.6.0 will not work with H2
databases created by earlier Dependency-Track versions.

For this reason, upgrading an existing Dependency-Track 4.5.x installation to 4.6.x requires a manual migration
of the H2 database beforehand. The migration procedure is outlined below.

1. Stop the Dependency-Track API server
2. Download the H2 v1.4.200 JAR and dump the existing database using the `Script` tool:
```shell
wget https://repo1.maven.org/maven2/com/h2database/h2/1.4.200/h2-1.4.200.jar
java -cp h2-1.4.200.jar org.h2.tools.Script \
  -url "jdbc:h2:file:~/.dependency-track/db" \
  -user sa -password ""
```
  * This will dump the database to a `backup.sql` file in the current working directory
3. Create a backup of the entire data directory, so you can easily roll back if something goes south during the next steps:
```shell
tar -czf dtrack-backup.tar.gz ~/.dependency-track
```
4. Delete the old H2 database and download H2 2.1.214:
```shell
rm -rf ~/.dependency-track/db.*
wget https://repo1.maven.org/maven2/com/h2database/h2/2.1.214/h2-2.1.214.jar
```
5. Launch the H2 shell using the H2 2.1.214 JAR and create a new database:
```shell
java -cp h2-2.1.214.jar org.h2.tools.Shell
Welcome to H2 Shell 2.1.214 (2022-06-13)
Exit with Ctrl+C
[Enter]   jdbc:h2:~/test
URL       jdbc:h2:~/.dependency-track/db
[Enter]   org.h2.Driver
Driver
[Enter]
User      sa
Password
Type the same password again to confirm database creation.
Password
Connected
sql> quit
```
6. If you haven't modified any database settings for your Dependency-Track instance, use the following values when prompted by the H2 shell:
  * URL: `jdbc:h2:~/.dependency-track/db`
  * Driver: `org.h2.Driver` (or just press Enter)
  * User: `sa`
  * Password: (Empty, just press Enter)
  * Once the shell confirms the successful creation with `Connected`, exit the shell using the `quit` command
7. Import `backup.sql` into the new database you just created using the `RunScript` tool:
```shell
java -cp h2-2.1.214.jar org.h2.tools.RunScript \
  -url jdbc:h2:~/.dependency-track/db \
  -user sa -password "" \
  -script backup.sql \
  -options quirks_mode variable_binary
```
8. That's it! It's now safe to start Dependency-Track 4.6.0


[About Pool Sizing]: https://github.com/brettwooldridge/HikariCP/wiki/About-Pool-Sizing
[Configuration]: {{ site.baseurl }}{% link _docs/getting-started/configuration.md %}
[HikariCP]: https://github.com/brettwooldridge/HikariCP
[Monitoring]: {{ site.baseurl }}{% link _docs/getting-started/monitoring.md %}
[SQL mode]: https://dev.mysql.com/doc/refman/5.7/en/sql-mode.html