create unlogged table dex_lease (
  name text
, acquired_by text not null
, acquired_at timestamptz(3) not null
, expires_at timestamptz(3) not null
, constraint dex_lease_pk primary key (name)
);

comment on table dex_lease
     is 'Leases for leader election';

create table dex_workflow_task_queue (
  name text
, partition_name text not null
, status text not null default 'ACTIVE'
, capacity smallint not null default 100
, created_at timestamptz(3) not null default now()
, updated_at timestamptz(3)
, constraint dex_workflow_task_queue_pk primary key (name)
, constraint dex_workflow_task_queue_status_check check (status in ('ACTIVE', 'PAUSED'))
, constraint dex_workflow_task_queue_capacity_check check (capacity > 0)
);

comment on table dex_workflow_task_queue
     is 'Workflow task queue metadata';

create table dex_workflow_run (
  id uuid
, parent_id uuid
, workflow_name text not null
, workflow_version smallint not null
, workflow_instance_id text
, task_queue_name text not null
, status text not null default 'CREATED'
, custom_status text
, concurrency_key text
, priority smallint not null default 0
, labels jsonb
, sticky_to text
, sticky_until timestamptz(3)
, created_at timestamptz(3) not null
, updated_at timestamptz(3)
, started_at timestamptz(3)
, completed_at timestamptz(3)
, constraint dex_workflow_run_pk primary key (id)
, constraint dex_workflow_run_parent_fk foreign key (parent_id) references dex_workflow_run (id) on delete cascade deferrable initially deferred
, constraint dex_workflow_run_task_queue_fk foreign key (task_queue_name) references dex_workflow_task_queue (name) on delete cascade deferrable initially deferred
, constraint dex_workflow_run_workflow_version check (workflow_version > 0 and workflow_version <= 100)
, constraint dex_workflow_run_status_check check (status in ('CREATED', 'RUNNING', 'SUSPENDED', 'CANCELED', 'COMPLETED', 'FAILED'))
, constraint dex_workflow_run_priority_check check (priority >= 0 and priority <= 100)
) with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 80);

comment on table dex_workflow_run
     is 'Workflow run metadata';

create table dex_workflow_task (
  queue_name text
, workflow_run_id uuid
, workflow_name text not null
, priority smallint not null
, sticky_to text
, sticky_until timestamptz(3)
, locked_by text
, locked_until timestamptz(3)
, lock_version smallint not null default 0
, created_at timestamptz(3) not null default now()
, constraint dex_workflow_task_pk primary key (queue_name, workflow_run_id)
, constraint dex_workflow_task_queue_fk foreign key (queue_name) references dex_workflow_task_queue (name) on delete cascade deferrable initially deferred
, constraint dex_workflow_task_workflow_run_fk foreign key (workflow_run_id) references dex_workflow_run (id) on delete cascade deferrable initially deferred
, constraint dex_workflow_task_priority_check check (priority >= 0 and priority <= 100)
) partition by list (queue_name);

comment on table dex_workflow_task
     is 'Workflow tasks queued for execution';

create table dex_workflow_history (
  workflow_run_id uuid
, sequence_number int
, event bytea not null
, constraint dex_workflow_history_pk primary key (workflow_run_id, sequence_number)
, constraint dex_workflow_history_workflow_run_fk foreign key (workflow_run_id) references dex_workflow_run (id) on delete cascade deferrable initially deferred
) partition by hash (workflow_run_id);

comment on table dex_workflow_history
     is 'Workflow run event history';

create table dex_workflow_history_p00 partition of dex_workflow_history for values with (modulus 8, remainder 0);
create table dex_workflow_history_p01 partition of dex_workflow_history for values with (modulus 8, remainder 1);
create table dex_workflow_history_p02 partition of dex_workflow_history for values with (modulus 8, remainder 2);
create table dex_workflow_history_p03 partition of dex_workflow_history for values with (modulus 8, remainder 3);
create table dex_workflow_history_p04 partition of dex_workflow_history for values with (modulus 8, remainder 4);
create table dex_workflow_history_p05 partition of dex_workflow_history for values with (modulus 8, remainder 5);
create table dex_workflow_history_p06 partition of dex_workflow_history for values with (modulus 8, remainder 6);
create table dex_workflow_history_p07 partition of dex_workflow_history for values with (modulus 8, remainder 7);

create table dex_workflow_inbox (
  id bigint generated always as identity
, workflow_run_id uuid not null
, visible_from timestamptz(3) not null default now()
, event bytea not null
, constraint dex_workflow_inbox_pk primary key (id)
, constraint dex_workflow_inbox_workflow_run_fk foreign key (workflow_run_id) references dex_workflow_run (id) on delete cascade deferrable initially deferred
) with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 80);

comment on table dex_workflow_inbox
     is 'Unprocessed workflow messages';

create table dex_activity_task_queue (
  name text
, partition_name text not null
, status text not null default 'ACTIVE'
, capacity smallint not null default 100
, created_at timestamptz(3) not null default now()
, updated_at timestamptz(3)
, constraint dex_activity_task_queue_pk primary key (name)
, constraint dex_activity_task_queue_status_check check (status in ('ACTIVE', 'PAUSED'))
, constraint dex_activity_task_queue_capacity_check check (capacity > 0)
);

comment on table dex_activity_task_queue
     is 'Activity task queue metadata';

create table dex_activity_task (
  queue_name text not null
, workflow_run_id uuid
, created_event_id int
, activity_name text not null
, priority smallint not null default 0
, status text not null default 'CREATED'
, argument bytea
, retry_policy bytea not null
, attempt smallint not null default 1
, visible_from timestamptz(3) not null default now()
, locked_by text
, locked_until timestamptz(3)
, lock_version smallint not null default 0
, created_at timestamptz(3) not null default now()
, updated_at timestamptz(3)
, constraint dex_activity_task_pk primary key (queue_name, workflow_run_id, created_event_id)
, constraint dex_activity_task_workflow_run_fk foreign key (workflow_run_id) references dex_workflow_run (id) on delete cascade deferrable initially deferred
, constraint dex_activity_task_queue_fk foreign key (queue_name) references dex_activity_task_queue (name)
, constraint dex_activity_task_status_check check (status in ('CREATED', 'QUEUED'))
, constraint dex_activity_task_priority_check check (priority >= 0 and priority <= 100)
) partition by list (queue_name);

comment on table dex_activity_task
     is 'Activity tasks to execute';

create index dex_workflow_run_task_scheduler_poll_idx
    on dex_workflow_run (task_queue_name, priority desc, id)
 where status in ('CREATED', 'RUNNING', 'SUSPENDED');

comment on index dex_workflow_run_task_scheduler_poll_idx
     is 'Support polling of the workflow task scheduler';

create unique index dex_workflow_run_workflow_instance_id_idx
    on dex_workflow_run (workflow_instance_id)
 where workflow_instance_id is not null
   and status in ('CREATED', 'RUNNING', 'SUSPENDED');

comment on index dex_workflow_run_workflow_instance_id_idx
     is 'Support enforcement of unique non-terminal workflow instance IDs';

create index dex_workflow_run_parent_id_idx
    on dex_workflow_run (parent_id)
 where parent_id is not null;

comment on index dex_workflow_run_parent_id_idx
     is 'Support workflow run lookups by parent ID';

create unique index dex_workflow_run_concurrency_key_executing_idx
    on dex_workflow_run (concurrency_key)
 where concurrency_key is not null
   and status in ('RUNNING', 'SUSPENDED');

comment on index dex_workflow_run_concurrency_key_executing_idx
     is 'Support identification of executing runs for a concurrency key';

create index dex_workflow_run_concurrency_key_next_idx
    on dex_workflow_run (concurrency_key, priority desc, id)
 where concurrency_key is not null
   and status = 'CREATED';

comment on index dex_workflow_run_concurrency_key_next_idx
     is 'Support identification of next run to execute for a concurrency key';

create index dex_workflow_run_labels_idx
    on dex_workflow_run using gin (labels jsonb_path_ops)
 where labels is not null;

comment on index dex_workflow_run_labels_idx
     is 'Support searching of workflow runs by label';

create index dex_workflow_run_created_at_idx
    on dex_workflow_run (created_at);

comment on index dex_workflow_run_created_at_idx
     is 'Support sorting of workflow runs by creation timestamp';

create index dex_workflow_run_completed_at_idx
    on dex_workflow_run (completed_at)
 where completed_at is not null;

comment on index dex_workflow_run_completed_at_idx
     is 'Support retention enforcement of completed workflow runs';

create index dex_workflow_task_poll_idx
    on dex_workflow_task (sticky_to, sticky_until, priority desc, workflow_run_id);

comment on index dex_workflow_task_poll_idx
     is 'Support polling of workflow task workers';

create index dex_workflow_inbox_workflow_run_id_idx
    on dex_workflow_inbox (workflow_run_id);

comment on index dex_workflow_inbox_workflow_run_id_idx
     is 'Support lookup of workflow messages by run ID';

create index dex_activity_task_scheduler_poll_idx
    on dex_activity_task (visible_from, priority desc, created_at)
 where status != 'QUEUED';

comment on index dex_activity_task_scheduler_poll_idx
     is 'Support polling of the activity task scheduler';

create index dex_activity_task_poll_idx
    on dex_activity_task (priority desc, created_at)
 where status = 'QUEUED';

comment on index dex_activity_task_poll_idx
     is 'Support polling of activity task workers';

create function dex_create_workflow_task_queue(queue_name text, queue_capacity smallint)
returns bool as $$
declare
  normalized_queue_name text;
  partition_name text;
  queue_created bool;
begin
  -- Ensure the name is OK to use for identifiers.
  select lower(regexp_replace(queue_name, '[^A-Za-z0-9_]', '_', 'g'))
    into normalized_queue_name;

  -- Ensure the partition name doesn't exceed the 63 characters limit.
  select format('dex_workflow_task_q_%s', left(normalized_queue_name, 43))
    into partition_name;

  with cte_created_queue as (
    insert into dex_workflow_task_queue (name, partition_name, capacity)
    values (queue_name, partition_name, queue_capacity)
    on conflict (name) do nothing
    returning 1
  )
  select exists(select 1 from cte_created_queue)
    into queue_created;

  if not queue_created then
    return false;
  end if;

  -- NB: Partitions are created as UNLOGGED to reduce I/O overhead.
  -- Data loss is acceptable for workflow tasks because they'll trivially
  -- be recreated by the task scheduler, based on the dex_workflow_run and
  -- dex_workflow_inbox tables.
  execute format($q$
    create unlogged table %I partition of dex_workflow_task for values in (%L)
      with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 85);
  $q$, partition_name, queue_name);

  return true;
end;
$$ language plpgsql;

create function dex_create_activity_task_queue(queue_name text, queue_capacity smallint)
returns bool as $$
declare
  normalized_queue_name text;
  partition_name text;
  queue_created bool;
begin
  -- Ensure the name is OK to use for identifiers.
  select lower(regexp_replace(queue_name, '[^A-Za-z0-9_]', '_', 'g'))
    into normalized_queue_name;

  -- Ensure the partition name doesn't exceed the 63 characters limit.
  select format('dex_activity_task_q_%s', left(normalized_queue_name, 43))
    into partition_name;

  with cte_created_queue as (
    insert into dex_activity_task_queue (name, partition_name, capacity)
    values (queue_name, partition_name, queue_capacity)
    on conflict (name) do nothing
    returning 1
  )
  select exists(select 1 from cte_created_queue)
    into queue_created;

  if not queue_created then
    return false;
  end if;

  execute format($q$
    create table %I partition of dex_activity_task for values in (%L)
      with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 85);
  $q$, partition_name, queue_name);

  return true;
end;
$$ language plpgsql;
