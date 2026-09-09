alter table dex_workflow_task
  add column if not exists concurrency_key text;

update dex_workflow_task
   set concurrency_key = run.concurrency_key
  from dex_workflow_run as run
 where run.id = workflow_run_id
   and run.concurrency_key is not null;

-- squawk-ignore require-concurrent-index-creation -- CONCURRENT is not supported on partitioned tables.
create index if not exists dex_workflow_task_queue_name_concurrency_key_idx
    on dex_workflow_task (queue_name, concurrency_key)
 where concurrency_key is not null;

comment on index dex_workflow_task_queue_name_concurrency_key_idx
     is 'Support the workflow task scheduler''s queued concurrency key checks';
