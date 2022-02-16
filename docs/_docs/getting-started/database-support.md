---
title: Database Support
category: Getting Started
chapter: 1
order: 6
---

Dependency-Track includes an embedded H2 database enabled by default. The intended purpose of this 
database is for quick evaluation, testing, and demonstration of the platform and its capabilities. 

> The embedded H2 database is not intended for production use.

Dependency-Track supports the following database servers:
* Microsoft SQL Server 2012 and higher
* MySQL 5.6 and 5.7
* PostgreSQL 9.0 and higher


To change database settings, edit `application.properties` found in the Dependency-Track data directory.


#### Microsoft SQL Server Example

```ini
alpine.database.mode=external
alpine.database.url=jdbc:sqlserver://localhost:1433;databaseName=dtrack;sendStringParametersAsUnicode=false
alpine.database.driver=com.microsoft.sqlserver.jdbc.SQLServerDriver
alpine.database.username=dtrack
alpine.database.password=password
```

#### MySQL Example

```ini
alpine.database.mode=external
alpine.database.url=jdbc:mysql://localhost:3306/dtrack?autoReconnect=true&useSSL=false
alpine.database.driver=com.mysql.jdbc.Driver
alpine.database.username=dtrack
alpine.database.password=password
```

For MySQL, it is necessary to remove 'NO_ZERO_IN_DATE' and 'NO_ZERO_DATE' from the sql-mode prior
to creating the Dependency-Track database. It's also necessary to add 'ANSI_QUOTES' to the sql-mode.
Refer to the MySQL documentation for details.

There are several ways to change this configuration, however the recommended way is to modify the
MySQL configuration (typically my.ini or similar) with the following:

```ini
[mysqld] 
sql_mode="ANSI_QUOTES,STRICT_TRANS_TABLES,ONLY_FULL_GROUP_BY,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
```

MySQL will erroneously report index key length violations ("Specified key was too long"), when infact the multi-byte
key length is lower than the actual value. If UTF-8 support is required, do not use MySQL.

#### PostgreSQL Example

```ini
alpine.database.mode=external
alpine.database.url=jdbc:postgresql://localhost:5432/dtrack
alpine.database.driver=org.postgresql.Driver
alpine.database.username=dtrack
alpine.database.password=password
```
