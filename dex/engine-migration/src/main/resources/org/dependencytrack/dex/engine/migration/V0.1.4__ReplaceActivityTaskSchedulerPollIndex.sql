-- squawk-ignore require-concurrent-index-creation -- CONCURRENT is not supported on partitioned tables.
create index if not exists dex_activity_task_scheduler_poll_v2_idx
    on dex_activity_task (priority desc, created_at, visible_from)
 where status != 'QUEUED';

comment on index dex_activity_task_scheduler_poll_v2_idx
     is 'Support polling of the activity task scheduler';

-- squawk-ignore require-concurrent-index-deletion -- CONCURRENT is not supported on partitioned tables.
drop index if exists dex_activity_task_scheduler_poll_idx;
