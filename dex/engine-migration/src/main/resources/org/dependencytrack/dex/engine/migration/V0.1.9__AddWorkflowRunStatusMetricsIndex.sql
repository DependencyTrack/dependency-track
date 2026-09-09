create index concurrently if not exists dex_workflow_run_status_metrics_idx
    on dex_workflow_run (workflow_name, status)
 where status in ('CREATED', 'RUNNING', 'SUSPENDED');
