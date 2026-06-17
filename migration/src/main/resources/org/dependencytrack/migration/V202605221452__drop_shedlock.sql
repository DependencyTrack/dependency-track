-- ShedLock is no longer needed after migrating task scheduling to db-scheduler.
DROP TABLE IF EXISTS shedlock;
