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
MySQL can require lots of extra care. **Only use MySQL if you know what you're doing**!

Refer to the [Configuration] documentation for how database settings may be changed.

### Examples



#### PostgreSQL

```yaml
# docker-compose.yml
version: "3"

services:
  postgres:
    image: postgres:14-alpine
    environment:
      POSTGRES_DB: "dtrack"
      POSTGRES_USER: "dtrack"
      POSTGRES_PASSWORD: "dtrack"
    volumes:
    - "postgres-data:/var/lib/postgresql/data"
    restart: unless-stopped
  
  apiserver:
    image: dependencytrack/apiserver:latest
    depends_on:
    - postgres
    environment:
      ALPINE_DATABASE_MODE: "external"
      ALPINE_DATABASE_URL: "jdbc:postgresql://postgres:5432/dtrack"
      ALPINE_DATABASE_DRIVER: "org.postgresql.Driver"
      ALPINE_DATABASE_USERNAME: "dtrack"
      ALPINE_DATABASE_PASSWORD: "dtrack"
    restart: unless-stopped

volumes:
  postgres-data: {}
```

#### Microsoft SQL Server

```yaml
# docker-compose.yml
version: "3"

services:
  sqlserver:
    image: mcr.microsoft.com/mssql/server:2022-latest
    environment:
      ACCEPT_EULA: "Y"
      SA_PASSWORD: "DTrack1234!"
    volumes:
    - "sqlserver-data:/var/opt/mssql/data"
    restart: unless-stopped

  apiserver:
    image: dependencytrack/apiserver:latest
    depends_on:
    - sqlserver
    environment:
      ALPINE_DATABASE_MODEL: "external"
      ALPINE_DATABASE_URL: "jdbc:sqlserver://sqlserver:1433;databaseName=dtrack;sendStringParametersAsUnicode=false;trustServerCertificate=true"
      ALPINE_DATABASE_DRIVER: "com.microsoft.sqlserver.jdbc.SQLServerDriver"
      ALPINE_DATABASE_USERNAME: "sa"
      ALPINE_DATABASE_PASSWORD: "DTrack1234!"
    restart: unless-stopped

volumes:
  sqlserver-data: {}
```

> Unlike other RDBMS, SQL Server does not automatically create a database for you.  
> Once the `sqlserver` container completed its starting sequence, a database can be created as follows:
> ```shell
> docker-compose exec sqlserver /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P 'DTrack1234!' -Q 'CREATE DATABASE dtrack'
> ```

#### MySQL

```yaml
# docker-compose.yml
version: "3"

services:
  mysql:
    image: mysql:5.7
    command:
    - --sql_mode="ANSI_QUOTES,STRICT_TRANS_TABLES,ONLY_FULL_GROUP_BY,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
    environment:
      MYSQL_RANDOM_ROOT_PASSWORD: "true"
      MYSQL_DATABASE: "dtrack"
      MYSQL_USER: "dtrack"
      MYSQL_PASSWORD: "dtrack"
    volumes:
    - "mysql-data:/var/lib/mysql"
    restart: unless-stopped

  apiserver:
    image: dependencytrack/apiserver:latest
    depends_on:
    - mysql
    environment:
      ALPINE_DATABASE_MODEL: "external"
      ALPINE_DATABASE_URL: "jdbc:mysql://localhost:3306/dtrack?autoReconnect=true&useSSL=false"
      ALPINE_DATABASE_DRIVER: "com.mysql.cj.jdbc.Driver"
      ALPINE_DATABASE_USERNAME: "dtrack"
      ALPINE_DATABASE_PASSWORD: "dtrack"
    restart: unless-stopped

volumes:
  mysql-data: {}
```

It is necessary to remove `NO_ZERO_IN_DATE` and `NO_ZERO_DATE` from the SQL mode prior to creating the 
Dependency-Track database. It's also necessary to add the `ANSI_QUOTES` SQL mode. 
Refer to the [MySQL documentation] for details.

There are several ways to change this configuration. The `docker-compose.yml` example above demonstrates how to do it
using `mysqld` command flags, however the recommended way is to modify the  MySQL configuration file 
(typically `my.ini` or similar) with the following:

```ini
[mysqld] 
sql_mode="ANSI_QUOTES,STRICT_TRANS_TABLES,ONLY_FULL_GROUP_BY,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
```

MySQL will erroneously report index key length violations ("Specified key was too long"), when infact the multi-byte
key length is lower than the actual value. **Do not use MySQL if don't know how to work around errors like this**!

[Configuration]: {{ site.baseurl }}{% link _docs/getting-started/configuration.md %}
[MySQL documentation]: https://dev.mysql.com/doc/refman/5.7/en/sql-mode.html