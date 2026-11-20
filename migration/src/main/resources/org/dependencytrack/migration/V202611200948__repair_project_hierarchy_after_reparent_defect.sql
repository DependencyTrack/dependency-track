-- Portfolios that reparented a project with descendants carry stale closure records that the
-- corrected trigger cannot repair on its own, because it only runs on the next update.
-- Rebuild the table from "PROJECT", which is the source of truth for the hierarchy.
DELETE FROM "PROJECT_HIERARCHY";

INSERT INTO "PROJECT_HIERARCHY" ("PARENT_PROJECT_ID", "CHILD_PROJECT_ID", "DEPTH")
WITH RECURSIVE hierarchy AS (
    SELECT "ID" AS parent_id
         , "ID" AS child_id
         , 0 AS depth
      FROM "PROJECT"
     UNION ALL
    SELECT hierarchy.parent_id
         , project."ID"
         , hierarchy.depth + 1
      FROM hierarchy
     INNER JOIN "PROJECT" AS project
        ON project."PARENT_PROJECT_ID" = hierarchy.child_id
)
SELECT parent_id
     , child_id
     , depth
  FROM hierarchy;
