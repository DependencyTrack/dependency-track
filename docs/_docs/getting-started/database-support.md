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

[Configuration]: {{ site.baseurl }}{% link _docs/getting-started/configuration.md %}
[SQL mode]: https://dev.mysql.com/doc/refman/5.7/en/sql-mode.html