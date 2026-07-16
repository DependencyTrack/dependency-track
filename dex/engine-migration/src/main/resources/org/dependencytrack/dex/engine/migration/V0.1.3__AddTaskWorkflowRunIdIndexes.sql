-- squawk-ignore require-concurrent-index-creation -- CONCURRENT is not supported on partitioned tables.
create index if not exists dex_workflow_task_workflow_run_id_idx
    on dex_workflow_task (workflow_run_id);

comment on index dex_workflow_task_workflow_run_id_idx
     is 'Support cascading deletes from dex_workflow_run during retention enforcement';

-- squawk-ignore require-concurrent-index-creation -- CONCURRENT is not supported on partitioned tables.
create index if not exists dex_activity_task_workflow_run_id_idx
    on dex_activity_task (workflow_run_id);

comment on index dex_activity_task_workflow_run_id_idx
     is 'Support cascading deletes from dex_workflow_run during retention enforcement';
