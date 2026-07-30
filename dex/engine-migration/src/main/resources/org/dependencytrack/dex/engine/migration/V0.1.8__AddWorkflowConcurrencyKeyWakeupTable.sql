create unlogged table if not exists dex_workflow_concurrency_key_wakeup (
  queue_name text not null
, concurrency_key text not null
-- squawk-ignore prefer-bigint-over-smallint
, priority smallint not null default 0
, version bigint not null default 0
, freed boolean not null default false
, created_at timestamptz(3) not null default clock_timestamp()
, constraint dex_workflow_concurrency_key_wakeup_pk primary key (queue_name, concurrency_key)
) with (autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.02);

comment on table dex_workflow_concurrency_key_wakeup
     is 'Advisory scheduling wakeup hints per concurrency key';

-- squawk-ignore require-concurrent-index-creation
create index if not exists dex_workflow_concurrency_key_wakeup_scan_idx
    on dex_workflow_concurrency_key_wakeup (queue_name, priority desc, freed desc, created_at);

comment on index dex_workflow_concurrency_key_wakeup_scan_idx
     is 'Support hint consumption by the workflow task scheduler';

