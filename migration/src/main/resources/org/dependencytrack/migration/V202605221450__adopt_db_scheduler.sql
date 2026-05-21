-- Adopt db-scheduler, see ADR-027.
CREATE TABLE scheduled_tasks (
  task_name TEXT NOT NULL
, task_instance TEXT NOT NULL
, task_data BYTEA
, execution_time TIMESTAMPTZ NOT NULL
, picked BOOLEAN NOT NULL
, picked_by TEXT
, last_success TIMESTAMPTZ
, last_failure TIMESTAMPTZ
, consecutive_failures INT
, last_heartbeat TIMESTAMPTZ
, version BIGINT NOT NULL
, priority SMALLINT
, CONSTRAINT scheduled_tasks_pk PRIMARY KEY (task_name, task_instance)
);

-- NB: We deliberately omit the indexes from db-scheduler's schema,
-- as they are not needed for our low task scheduling volume.
-- We can add them in the future if needed.
--
--   CREATE INDEX scheduled_tasks_execution_time_idx ON scheduled_tasks (execution_time);
--   CREATE INDEX scheduled_tasks_last_heartbeat_idx ON scheduled_tasks (last_heartbeat);
--   CREATE INDEX scheduled_tasks_priority_execution_time_idx ON scheduled_tasks (priority DESC, execution_time ASC);

-- Carry existing recurring tasks over so db-scheduler treats them as known on
-- the next startup, rather than as first-time registrations.
-- execution_time is seeded in the future because db-scheduler only realigns
-- a task to its schedule when the stored value is more than 10s ahead of now().
-- A past value would run on the first poll.
INSERT INTO scheduled_tasks (task_name, task_instance, execution_time, picked, version)
SELECT "TASK_ID"
     , 'recurring'
     , now() + INTERVAL '1 hour'
     , FALSE
     , 1
  FROM "SCHEDULED_TASK_EXECUTION"
 -- Internal component identification is no longer a scheduled task.
 WHERE "TASK_ID" != 'Internal Component Identification';

DROP TABLE "SCHEDULED_TASK_EXECUTION";
