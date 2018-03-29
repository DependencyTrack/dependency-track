Upgrade Notes
=========

This directory contains a scripts and other information that may be necessary to execute prior to upgrading.

SQL Scripts (Manual)
-------------------

To upgrade, shutdown Dependency-Track and execute the script for the version you're upgrading from to the version
being upgraded to. The scripts must be executed prior to upgrades.

SQL Scripts (Automated)
-------------------

It's highly recommended that Dependency-Track users manage their database schemas through tools like 
[Liquibase](https://www.liquibase.org/) or [Flyway](https://flywaydb.org/). The automatic creation of 
schema columns, indexes, and constraints is part of the Dependency-Track startup process. However, if 
indexes, columns, or constraints are altered or removed between versions, tools like Liquibase and Flyway
can assist in automating the versioning and migration of the schema without much need for manual intervention.