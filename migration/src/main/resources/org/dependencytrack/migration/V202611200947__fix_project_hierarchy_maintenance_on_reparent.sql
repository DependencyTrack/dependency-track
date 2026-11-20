-- The previous version of this function rebuilt the closure records of the updated project
-- only. Descendants kept the records pointing at their former ancestors and never received
-- records for the new ones, so portfolio access control did not reach them: a team granted
-- access to the new ancestor saw the moved project but got 403 on its children.
CREATE OR REPLACE FUNCTION project_hierarchy_maintenance_on_project_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              -- Detach the updated project and all of its descendants from their former ancestors.
              -- Records within the moved subtree stay valid, the self-referential ones included.
              DELETE FROM "PROJECT_HIERARCHY"
               WHERE "CHILD_PROJECT_ID" IN (
                       SELECT "CHILD_PROJECT_ID"
                         FROM "PROJECT_HIERARCHY"
                        WHERE "PARENT_PROJECT_ID" = NEW."ID")
                 AND "PARENT_PROJECT_ID" NOT IN (
                       SELECT "CHILD_PROJECT_ID"
                         FROM "PROJECT_HIERARCHY"
                        WHERE "PARENT_PROJECT_ID" = NEW."ID");

              -- Attach the subtree to the new parent and to each ancestor of the new parent.
              -- A NULL new parent has no ancestors, leaving the subtree at the root.
              INSERT INTO "PROJECT_HIERARCHY" ("PARENT_PROJECT_ID", "CHILD_PROJECT_ID", "DEPTH")
              SELECT ancestor."PARENT_PROJECT_ID"
                   , descendant."CHILD_PROJECT_ID"
                   , ancestor."DEPTH" + descendant."DEPTH" + 1
                FROM "PROJECT_HIERARCHY" AS ancestor
               CROSS JOIN "PROJECT_HIERARCHY" AS descendant
               WHERE ancestor."CHILD_PROJECT_ID" = NEW."PARENT_PROJECT_ID"
                 AND descendant."PARENT_PROJECT_ID" = NEW."ID";

              RETURN NEW;
            END;
            $$;
