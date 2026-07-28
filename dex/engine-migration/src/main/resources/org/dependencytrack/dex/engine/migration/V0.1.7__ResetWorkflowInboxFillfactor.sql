-- Inbox rows are inserted once and deleted on consumption, never updated.
-- Reserving page space for HOT updates via a reduced fillfactor only lowers page density.
-- squawk-ignore prefer-robust-stmts -- RESET is a no-op when already reset.
alter table dex_workflow_inbox reset (fillfactor);
