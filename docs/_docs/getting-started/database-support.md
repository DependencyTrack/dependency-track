---
title: Database Support
category: Getting Started
chapter: 1
order: 5
---

Dependency-Track includes an embedded H2 database enabled by default. The intended purpose of this 
database is for quick evaluation, testing, and demonstration of the platform and its capabilities. 

> The embedded H2 database is not intended for production use.

Dependency-Track has been tested with and supports the following external database servers:
* Microsoft SQL Server 2012 and higher
* MySQL 5.6 and higher


To change database settings, edit `application.properties` found in the Dependency-Track data directory.


The following parameters can be customized:
* alpine.database.mode
* alpine.database.url
* alpine.database.driver
* alpine.database.driver.path
* alpine.database.username
* alpine.database.password

#### Microsoft SQL Server Example

```ini
alpine.database.mode=external
alpine.database.url=jdbc:sqlserver://localhost:1433;databaseName=dtrack
alpine.database.driver=com.microsoft.sqlserver.jdbc.SQLServerDriver
alpine.database.driver.path=~/path/to/sqljdbc4.jar
alpine.database.username=dtrack
alpine.database.password=password
```

#### MySQL Example

For MySQL, it is necessary to remove 'NO_ZERO_IN_DATE' and 'NO_ZERO_DATE' from the sql-mode prior
to creating the Dependency-Track database. Refer to the MySQL documentation for details.

```ini
alpine.database.mode=external
alpine.database.url=jdbc:mysql://localhost:3306/dtrack?autoReconnect=true&useSSL=false
alpine.database.driver=com.mysql.jdbc.Driver
alpine.database.driver.path=~/path/to/mysql-connector-java-5.1.45-bin.jar
alpine.database.username=dtrack
alpine.database.password=password
```
