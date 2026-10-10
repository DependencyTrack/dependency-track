create index concurrently if not exists dex_workflow_run_root_created_at_idx
    on dex_workflow_run (created_at desc, id desc)
 where parent_id is null;
