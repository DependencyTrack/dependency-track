-- Include visible_from so the task scheduler's visible-message lookup
-- can be satisfied by an index-only scan, avoiding one heap fetch per
-- inbox message during scheduling polls.
create index concurrently if not exists dex_workflow_inbox_workflow_run_id_visible_from_idx
    on dex_workflow_inbox (workflow_run_id, visible_from);

drop index concurrently if exists dex_workflow_inbox_workflow_run_id_idx;

-- Split the workflow task scheduler poll index into two partial indexes
-- whose predicates match the scheduling query's UNION ALL arms exactly.
create index concurrently if not exists dex_workflow_run_task_scheduler_poll_keyless_idx
    on dex_workflow_run (task_queue_name, priority desc, id)
 where status = 'CREATED' and concurrency_key is null;

create index concurrently if not exists dex_workflow_run_task_scheduler_poll_executing_idx
    on dex_workflow_run (task_queue_name, priority desc, id)
 where status in ('RUNNING', 'SUSPENDED');

drop index concurrently if exists dex_workflow_run_task_scheduler_poll_idx;
