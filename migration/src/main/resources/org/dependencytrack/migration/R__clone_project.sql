CREATE OR REPLACE FUNCTION clone_project(
  source_project_uuid UUID
, target_project_version TEXT
, target_project_version_is_latest BOOL DEFAULT FALSE
, include_acl BOOL DEFAULT TRUE
, include_components BOOL DEFAULT TRUE
, include_findings BOOL DEFAULT TRUE
, include_findings_audit_history BOOL DEFAULT TRUE
, include_policy_violations BOOL DEFAULT TRUE
, include_policy_violations_audit_history BOOL DEFAULT TRUE
, include_properties BOOL DEFAULT TRUE
, include_services BOOL DEFAULT TRUE
, include_tags BOOL DEFAULT TRUE
) RETURNS UUID
  LANGUAGE "plpgsql"
  VOLATILE
  PARALLEL UNSAFE
AS
$$
DECLARE
  source_project RECORD;
  target_project RECORD;
BEGIN
  -- Defer checking of FK constraints to commit time.
  -- We want clones to be atomic, but due to the multiple tables
  -- with FKs being involved, that has a potential for lock contention.
  SET CONSTRAINTS ALL DEFERRED;

  -- Determine details of the project to be cloned.
  SELECT "ID" AS id
       , "UUID" AS uuid
       , "NAME" AS name
    FROM "PROJECT"
   WHERE "UUID" = source_project_uuid
    INTO source_project;

  IF source_project IS NULL THEN
    RAISE EXCEPTION 'Source project does not exist: %', source_project_uuid;
  END IF;

  IF EXISTS(SELECT 1 FROM "PROJECT" WHERE "NAME" = source_project.name AND "VERSION" = target_project_version) THEN
    RAISE EXCEPTION 'Target project version already exists: %', target_project_version;
  END IF;

  -- Clone the project itself.
  WITH created_project AS (
    INSERT INTO "PROJECT" (
      "AUTHORS"
    , "MANUFACTURER"
    , "SUPPLIER"
    , "PUBLISHER"
    , "GROUP"
    , "NAME"
    , "VERSION"
    , "DESCRIPTION"
    , "CLASSIFIER"
    , "INACTIVE_SINCE"
    , "CPE"
    , "PURL"
    , "SWIDTAGID"
    , "DIRECT_DEPENDENCIES"
    , "PARENT_PROJECT_ID"
    , "COLLECTION_LOGIC"
    , "COLLECTION_TAG_ID"
    , "UUID"
    )
    SELECT "AUTHORS"
         , "MANUFACTURER"
         , "SUPPLIER"
         , "PUBLISHER"
         , "GROUP"
         , "NAME"
         , target_project_version
         , "DESCRIPTION"
         , "CLASSIFIER"
         , "INACTIVE_SINCE"
         , "CPE"
         , "PURL"
         , "SWIDTAGID"
         , "DIRECT_DEPENDENCIES"
         , "PARENT_PROJECT_ID"
         , "COLLECTION_LOGIC"
         , "COLLECTION_TAG_ID"
         , gen_random_uuid()
      FROM "PROJECT"
     WHERE "UUID" = source_project_uuid
    RETURNING "ID", "UUID"
  )
  SELECT "ID" AS id
       , "UUID" AS uuid
    FROM created_project
    INTO target_project;

  -- Clone project metadata.
  INSERT INTO "PROJECT_METADATA" (
    "PROJECT_ID"
  , "AUTHORS"
  , "SUPPLIER"
  , "TOOLS"
  )
  SELECT target_project.id
       , "AUTHORS"
       , "SUPPLIER"
       , "TOOLS"
    FROM "PROJECT_METADATA"
   WHERE "PROJECT_ID" = source_project.id;

  -- Clone project properties.
  IF include_properties THEN
    INSERT INTO "PROJECT_PROPERTY" (
      "PROJECT_ID"
    , "GROUPNAME"
    , "PROPERTYNAME"
    , "PROPERTYTYPE"
    , "PROPERTYVALUE"
    , "DESCRIPTION"
    )
    SELECT target_project.id
         , "GROUPNAME"
         , "PROPERTYNAME"
         , "PROPERTYTYPE"
         , "PROPERTYVALUE"
         , "DESCRIPTION"
      FROM "PROJECT_PROPERTY"
     WHERE "PROJECT_ID" = source_project.id
     ORDER BY "GROUPNAME"
            , "PROPERTYNAME";
  END IF;

  -- Clone tag relationships.
  IF include_tags THEN
    INSERT INTO "PROJECTS_TAGS" ("PROJECT_ID", "TAG_ID")
    SELECT target_project.id
         , "TAG_ID"
      FROM "PROJECTS_TAGS"
     WHERE "PROJECT_ID" = source_project.id
     ORDER BY "TAG_ID";
  END IF;

  -- Clone portfolio ACL definitions.
  IF include_acl THEN
    INSERT INTO "PROJECT_ACCESS_TEAMS" ("PROJECT_ID", "TEAM_ID")
    SELECT target_project.id
         , "TEAM_ID"
      FROM "PROJECT_ACCESS_TEAMS"
     WHERE "PROJECT_ID" = source_project.id
     ORDER BY "TEAM_ID";
  END IF;

  -- Clone components.
  IF include_components THEN
    -- Maintain a mapping of IDs between source and target components
    -- in order to be able to clone their relationships.
    --
    -- NB: Target IDs and UUIDs are allocated upfront, so that parent and dependency
    -- references can be rewired during the insert, without updating rows afterwards.
    CREATE TEMP TABLE tmp_component_mapping (
      source_id BIGINT
    , source_uuid UUID
    , target_id BIGINT
    , target_uuid UUID
    ) ON COMMIT DROP;

    INSERT INTO tmp_component_mapping (
      source_id
    , source_uuid
    , target_id
    , target_uuid
    )
    SELECT "ID"
         , "UUID"
         , NEXTVAL('"COMPONENT_ID_seq"')
         , gen_random_uuid()
      FROM "COMPONENT"
     WHERE "PROJECT_ID" = source_project.id
     ORDER BY "ID";

    WITH
    -- NB: Using MATERIALIZED prevents the planner from expanding dependencies
    -- in a nested loop that scans the entire mapping once per component.
    source_dependency AS MATERIALIZED (
      SELECT c."ID" AS component_id
           , dep.value AS dep
           , dep.ordinality
        FROM "COMPONENT" AS c
       CROSS JOIN JSONB_ARRAY_ELEMENTS(c."DIRECT_DEPENDENCIES") WITH ORDINALITY AS dep
       WHERE c."PROJECT_ID" = source_project.id
    ),
    target_dependencies AS (
      SELECT source_dependency.component_id
           , JSONB_AGG(
               CASE
                 WHEN tmp_component_mapping.target_uuid IS NULL
                 THEN source_dependency.dep
                 ELSE JSONB_SET(source_dependency.dep, '{uuid}', TO_JSONB(tmp_component_mapping.target_uuid::TEXT))
               END
               ORDER BY source_dependency.ordinality
             ) AS deps
        FROM source_dependency
        LEFT JOIN tmp_component_mapping
          ON tmp_component_mapping.source_uuid::TEXT = source_dependency.dep->>'uuid'
       GROUP BY source_dependency.component_id
    )
    INSERT INTO "COMPONENT" (
      "ID"
    , "PROJECT_ID"
    , "GROUP"
    , "NAME"
    , "VERSION"
    , "CLASSIFIER"
    , "FILENAME"
    , "EXTENSION"
    , "MD5"
    , "SHA1"
    , "SHA_256"
    , "SHA_384"
    , "SHA_512"
    , "SHA3_256"
    , "SHA3_384"
    , "SHA3_512"
    , "BLAKE2B_256"
    , "BLAKE2B_384"
    , "BLAKE2B_512"
    , "BLAKE3"
    , "STREEBOG_256"
    , "STREEBOG_512"
    , "CPE"
    , "PURL"
    , "PURLCOORDINATES"
    , "SWIDTAGID"
    , "INTERNAL"
    , "DESCRIPTION"
    , "COPYRIGHT"
    , "LICENSE"
    , "LICENSE_ID"
    , "LICENSE_EXPRESSION"
    , "LICENSE_URL"
    , "AUTHORS"
    , "SUPPLIER"
    , "DIRECT_DEPENDENCIES"
    , "PARENT_COMPONENT_ID"
    , "UUID"
    )
    SELECT component_mapping.target_id
         , target_project.id
         , c."GROUP"
         , c."NAME"
         , c."VERSION"
         , c."CLASSIFIER"
         , c."FILENAME"
         , c."EXTENSION"
         , c."MD5"
         , c."SHA1"
         , c."SHA_256"
         , c."SHA_384"
         , c."SHA_512"
         , c."SHA3_256"
         , c."SHA3_384"
         , c."SHA3_512"
         , c."BLAKE2B_256"
         , c."BLAKE2B_384"
         , c."BLAKE2B_512"
         , c."BLAKE3"
         , c."STREEBOG_256"
         , c."STREEBOG_512"
         , c."CPE"
         , c."PURL"
         , c."PURLCOORDINATES"
         , c."SWIDTAGID"
         , c."INTERNAL"
         , c."DESCRIPTION"
         , c."COPYRIGHT"
         , c."LICENSE"
         , c."LICENSE_ID"
         , c."LICENSE_EXPRESSION"
         , c."LICENSE_URL"
         , c."AUTHORS"
         , c."SUPPLIER"
         , COALESCE(target_dependencies.deps, c."DIRECT_DEPENDENCIES")
         , COALESCE(parent_mapping.target_id, c."PARENT_COMPONENT_ID")
         , component_mapping.target_uuid
      FROM tmp_component_mapping AS component_mapping
     INNER JOIN "COMPONENT" AS c
        ON c."ID" = component_mapping.source_id
      LEFT JOIN tmp_component_mapping AS parent_mapping
        ON parent_mapping.source_id = c."PARENT_COMPONENT_ID"
      LEFT JOIN target_dependencies
        ON target_dependencies.component_id = c."ID";

    -- Clone component licenses.
    INSERT INTO "COMPONENTLICENSES" (
      "COMPONENT_ID",
      "LICENSE_ID",
      "LICENSE",
      "LICENSE_EXPRESSION",
      "LICENSE_URL",
      "ORDINALITY",
      "ACKNOWLEDGEMENT"
    )
    SELECT
        tmp_component_mapping."target_id",
        cl."LICENSE_ID",
        cl."LICENSE",
        cl."LICENSE_EXPRESSION",
        cl."LICENSE_URL",
        cl."ORDINALITY",
        cl."ACKNOWLEDGEMENT"
    FROM tmp_component_mapping
    JOIN "COMPONENTLICENSES" AS cl
      ON cl."COMPONENT_ID" = tmp_component_mapping."source_id";

    -- Clone component occurrences.
    INSERT INTO "COMPONENT_OCCURRENCE" (
      "COMPONENT_ID"
    , "ID"
    , "LOCATION"
    , "LINE"
    , "OFFSET"
    , "SYMBOL"
    , "CREATED_AT"
    )
    SELECT tmp_component_mapping.target_id
         , odt_uuidv7()
         , co."LOCATION"
         , co."LINE"
         , co."OFFSET"
         , co."SYMBOL"
         , co."CREATED_AT"
      FROM tmp_component_mapping
     INNER JOIN "COMPONENT_OCCURRENCE" AS co
        ON co."COMPONENT_ID" = tmp_component_mapping.source_id
     ORDER BY tmp_component_mapping.target_id;

    -- Clone component properties.
    INSERT INTO "COMPONENT_PROPERTY" (
      "COMPONENT_ID"
    , "GROUPNAME"
    , "PROPERTYNAME"
    , "PROPERTYTYPE"
    , "PROPERTYVALUE"
    , "DESCRIPTION"
    , "UUID"
    )
    SELECT tmp_component_mapping.target_id
         , "GROUPNAME"
         , "PROPERTYNAME"
         , "PROPERTYTYPE"
         , "PROPERTYVALUE"
         , "DESCRIPTION"
         , gen_random_uuid()
      FROM tmp_component_mapping
     INNER JOIN "COMPONENT_PROPERTY"
        ON "COMPONENT_ID" = tmp_component_mapping.source_id
     ORDER BY tmp_component_mapping.target_id
            , "GROUPNAME"
            , "PROPERTYNAME";

    -- Clone component findings.
    IF include_findings THEN
      INSERT INTO "COMPONENTS_VULNERABILITIES" ("COMPONENT_ID", "VULNERABILITY_ID")
      SELECT tmp_component_mapping.target_id
           , cv."VULNERABILITY_ID"
        FROM "COMPONENTS_VULNERABILITIES" AS cv
       INNER JOIN tmp_component_mapping
          ON tmp_component_mapping.source_id = cv."COMPONENT_ID"
       WHERE EXISTS (
         SELECT 1
           FROM "FINDINGATTRIBUTION" AS fa
          WHERE fa."COMPONENT_ID" = cv."COMPONENT_ID"
            AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
            AND fa."PROJECT_ID" = source_project.id
            AND fa."DELETED_AT" IS NULL
       )
       ORDER BY cv."VULNERABILITY_ID"
              , tmp_component_mapping.target_id;

      INSERT INTO "FINDINGATTRIBUTION" (
        "PROJECT_ID"
      , "COMPONENT_ID"
      , "VULNERABILITY_ID"
      , "ALT_ID"
      , "ANALYZERIDENTITY"
      , "ATTRIBUTED_ON"
      , "REFERENCE_URL"
      )
      SELECT target_project.id
           , tmp_component_mapping.target_id
           , fa."VULNERABILITY_ID"
           , fa."ALT_ID"
           , fa."ANALYZERIDENTITY"
           , fa."ATTRIBUTED_ON"
           , fa."REFERENCE_URL"
        FROM "FINDINGATTRIBUTION" AS fa
       INNER JOIN tmp_component_mapping
          ON tmp_component_mapping.source_id = fa."COMPONENT_ID"
       WHERE fa."PROJECT_ID" = source_project.id
         AND fa."DELETED_AT" IS NULL
       ORDER BY fa."VULNERABILITY_ID"
              , tmp_component_mapping.target_id;

      IF include_findings_audit_history THEN
        WITH
        source_analysis AS (
          SELECT *
               , ROW_NUMBER() OVER(ORDER BY "ID") AS rn
            FROM "ANALYSIS" AS a
           WHERE a."PROJECT_ID" = source_project.id
             AND EXISTS (
               SELECT 1
                 FROM "FINDINGATTRIBUTION" AS fa
                WHERE fa."COMPONENT_ID" = a."COMPONENT_ID"
                  AND fa."VULNERABILITY_ID" = a."VULNERABILITY_ID"
                  AND fa."PROJECT_ID" = source_project.id
                  AND fa."DELETED_AT" IS NULL
             )
        ),
        target_analysis AS (
          INSERT INTO "ANALYSIS" (
            "COMPONENT_ID"
          , "PROJECT_ID"
          , "VULNERABILITY_ID"
          , "VULNERABILITY_POLICY_ID"
          , "DETAILS"
          , "JUSTIFICATION"
          , "RESPONSE"
          , "STATE"
          , "SUPPRESSED"
          , "CVSSV2VECTOR"
          , "CVSSV3SCORE"
          , "OWASPSCORE"
          , "CVSSV2SCORE"
          , "OWASPVECTOR"
          , "CVSSV3VECTOR"
          , "SEVERITY"
          , "CVSSV4SCORE"
          , "CVSSV4VECTOR"
          )
          SELECT tmp_component_mapping.target_id
               , target_project.id
               , "VULNERABILITY_ID"
               , "VULNERABILITY_POLICY_ID"
               , "DETAILS"
               , "JUSTIFICATION"
               , "RESPONSE"
               , "STATE"
               , "SUPPRESSED"
               , "CVSSV2VECTOR"
               , "CVSSV3SCORE"
               , "OWASPSCORE"
               , "CVSSV2SCORE"
               , "OWASPVECTOR"
               , "CVSSV3VECTOR"
               , "SEVERITY"
               , "CVSSV4SCORE"
               , "CVSSV4VECTOR"
            FROM source_analysis
           INNER JOIN tmp_component_mapping
              ON tmp_component_mapping.source_id = "COMPONENT_ID"
           ORDER BY rn
          RETURNING "ID"
        ),
        target_analysis_ranked AS (
          SELECT *
               , ROW_NUMBER() OVER() AS rn
            FROM target_analysis
        ),
        analysis_mapping AS (
          SELECT source_analysis."ID" AS source_id
               , target_analysis_ranked."ID" AS target_id
            FROM source_analysis
           INNER JOIN target_analysis_ranked
              ON target_analysis_ranked.rn = source_analysis.rn
        )
        INSERT INTO "ANALYSISCOMMENT" ("ANALYSIS_ID", "COMMENT", "COMMENTER", "TIMESTAMP")
        SELECT analysis_mapping.target_id
             , "COMMENT"
             , "COMMENTER"
             , "TIMESTAMP"
          FROM "ANALYSISCOMMENT"
         INNER JOIN analysis_mapping
            ON analysis_mapping.source_id = "ANALYSIS_ID";
      END IF; -- include_findings_audit_history
    END IF; -- include_findings

    IF include_policy_violations THEN
      CREATE TEMP TABLE tmp_violation_mapping (
        source_id BIGINT
      , target_id BIGINT
      ) ON COMMIT DROP;

      WITH
      source_violation AS (
        SELECT *
             , ROW_NUMBER() OVER(ORDER BY "ID") AS rn
          FROM "POLICYVIOLATION"
         WHERE "PROJECT_ID" = source_project.id
      ),
      target_violation AS (
        INSERT INTO "POLICYVIOLATION" (
          "COMPONENT_ID"
        , "PROJECT_ID"
        , "POLICYCONDITION_ID"
        , "TEXT"
        , "TIMESTAMP"
        , "TYPE"
        , "UUID"
        )
        SELECT tmp_component_mapping.target_id
             , target_project.id
             , "POLICYCONDITION_ID"
             , "TEXT"
             , "TIMESTAMP"
             , "TYPE"
             , gen_random_uuid()
          FROM source_violation
         INNER JOIN tmp_component_mapping
            ON tmp_component_mapping.source_id = "COMPONENT_ID"
         ORDER BY rn
        RETURNING "ID"
      ),
      target_violation_ranked AS (
        SELECT *
             , ROW_NUMBER() OVER() AS rn
          FROM target_violation
      )
      INSERT INTO tmp_violation_mapping (source_id, target_id)
      SELECT source_violation."ID" AS source_id
           , target_violation_ranked."ID" AS target_id
        FROM source_violation
       INNER JOIN target_violation_ranked
          ON target_violation_ranked.rn = source_violation.rn;

      IF include_policy_violations_audit_history THEN
        WITH
        source_violation_analysis AS (
          SELECT *
               , ROW_NUMBER() OVER(ORDER BY "ID") AS rn
            FROM "VIOLATIONANALYSIS"
           WHERE "PROJECT_ID" = source_project.id
        ),
        target_violation_analysis AS (
          INSERT INTO "VIOLATIONANALYSIS" (
            "COMPONENT_ID"
          , "PROJECT_ID"
          , "POLICYVIOLATION_ID"
          , "STATE"
          , "SUPPRESSED"
          )
          SELECT tmp_component_mapping.target_id
               , target_project.id
               , tmp_violation_mapping.target_id
               , "STATE"
               , "SUPPRESSED"
            FROM source_violation_analysis
           INNER JOIN tmp_component_mapping
              ON tmp_component_mapping.source_id = "COMPONENT_ID"
           INNER JOIN tmp_violation_mapping
              ON tmp_violation_mapping.source_id = "POLICYVIOLATION_ID"
           ORDER BY source_violation_analysis.rn
          RETURNING "ID"
        ),
        target_violation_analysis_ranked AS (
          SELECT *
               , ROW_NUMBER() OVER() AS rn
            FROM target_violation_analysis
        ),
        violation_analysis_mapping AS (
          SELECT source_violation_analysis."ID" AS source_id
               , target_violation_analysis_ranked."ID" AS target_id
            FROM source_violation_analysis
           INNER JOIN target_violation_analysis_ranked
              ON target_violation_analysis_ranked.rn = source_violation_analysis.rn
        )
        INSERT INTO "VIOLATIONANALYSISCOMMENT" ("VIOLATIONANALYSIS_ID", "COMMENT", "COMMENTER", "TIMESTAMP")
        SELECT violation_analysis_mapping.target_id
             , "COMMENT"
             , "COMMENTER"
             , "TIMESTAMP"
          FROM "VIOLATIONANALYSISCOMMENT"
         INNER JOIN violation_analysis_mapping
            ON violation_analysis_mapping.source_id = "VIOLATIONANALYSIS_ID";
      END IF; -- include_policy_violations_audit_history

      DROP TABLE tmp_violation_mapping;
    END IF; -- include_policy_violations

    -- Rewire project dependencies.
    --
    -- Flatten the DIRECT_DEPENDENCIES array into a temporary table
    -- to make it more efficient to modify.
    CREATE TEMP TABLE tmp_project_direct_deps ON COMMIT DROP AS
    SELECT JSONB_ARRAY_ELEMENTS("DIRECT_DEPENDENCIES") AS dep
      FROM "PROJECT"
     WHERE "ID" = target_project.id
       AND "DIRECT_DEPENDENCIES" IS NOT NULL;

    UPDATE tmp_project_direct_deps
       SET dep = JSONB_SET(dep, '{uuid}', TO_JSONB(tmp_component_mapping.target_uuid::TEXT))
      FROM tmp_component_mapping
     WHERE dep->>'uuid' = tmp_component_mapping.source_uuid::TEXT;

    UPDATE "PROJECT"
       SET "DIRECT_DEPENDENCIES" = (
             SELECT JSONB_AGG(dep)
               FROM tmp_project_direct_deps
           )
     WHERE "ID" = target_project.id
       AND EXISTS(SELECT 1 FROM tmp_project_direct_deps);

    DROP TABLE tmp_project_direct_deps;

    DROP TABLE tmp_component_mapping;
  END IF;

  -- Clone services.
  IF include_services THEN
    CREATE TEMP TABLE tmp_service_mapping (
      source_id BIGINT
    , target_id BIGINT
    ) ON COMMIT DROP;

    WITH
    source_service AS (
      SELECT *
           , ROW_NUMBER() OVER(ORDER BY "ID") AS rn
        FROM "SERVICECOMPONENT"
       WHERE "PROJECT_ID" = source_project.id
    ),
    target_service AS (
      INSERT INTO "SERVICECOMPONENT" (
        "PROJECT_ID"
      , "GROUP"
      , "NAME"
      , "VERSION"
      , "DESCRIPTION"
      , "PROVIDER_ID"
      , "ENDPOINTS"
      , "AUTHENTICATED"
      , "X_TRUST_BOUNDARY"
      , "DATA"
      , "EXTERNAL_REFERENCES"
      , "LAST_RISKSCORE"
      , "TEXT"
      , "PARENT_SERVICECOMPONENT_ID"
      , "UUID"
      )
      SELECT target_project.id
           , "GROUP"
           , "NAME"
           , "VERSION"
           , "DESCRIPTION"
           , "PROVIDER_ID"
           , "ENDPOINTS"
           , "AUTHENTICATED"
           , "X_TRUST_BOUNDARY"
           , "DATA"
           , "EXTERNAL_REFERENCES"
           , "LAST_RISKSCORE"
           , "TEXT"
           , "PARENT_SERVICECOMPONENT_ID"
           , gen_random_uuid()
          FROM source_service
       ORDER BY rn
      RETURNING "ID"
    ),
    target_service_ranked AS (
      SELECT *
           , ROW_NUMBER() OVER() AS rn
        FROM target_service
    )
    INSERT INTO tmp_service_mapping (source_id, target_id)
    SELECT source_service."ID"
         , target_service_ranked."ID"
      FROM source_service
     INNER JOIN target_service_ranked
        ON target_service_ranked.rn = source_service.rn;

    -- Update parent service references.
    UPDATE "SERVICECOMPONENT"
       SET "PARENT_SERVICECOMPONENT_ID" = tmp_service_mapping.target_id
      FROM tmp_service_mapping
     WHERE "PROJECT_ID" = target_project.id
       AND tmp_service_mapping.source_id = "PARENT_SERVICECOMPONENT_ID";

    -- Clone service findings.
    IF include_findings THEN
      INSERT INTO "SERVICECOMPONENTS_VULNERABILITIES" ("SERVICECOMPONENT_ID", "VULNERABILITY_ID")
      SELECT tmp_service_mapping.target_id
           , "VULNERABILITY_ID"
        FROM "SERVICECOMPONENTS_VULNERABILITIES"
       INNER JOIN tmp_service_mapping
          ON tmp_service_mapping.source_id = "SERVICECOMPONENT_ID"
      ORDER BY "VULNERABILITY_ID"
             , tmp_service_mapping.target_id;
    END IF; -- include_findings

    DROP TABLE tmp_service_mapping;
  END IF; -- include_services

  -- When the target project is supposed to be the latest version,
  -- ensure the previous latest version is no longer marked as such.
  --
  -- This can acquire an exclusive lock on the project row that is currently
  -- marked latest, potentially blocking other transactions that also want
  -- to modify that row. To avoid long wait times, we perform this operation
  -- at the very end, reducing the duration for which this lock may be held.
  IF target_project_version_is_latest THEN
    UPDATE "PROJECT"
       SET "IS_LATEST" = FALSE
     WHERE "NAME" = source_project.name
       AND "IS_LATEST";

    UPDATE "PROJECT"
       SET "IS_LATEST" = TRUE
     WHERE "ID" = target_project.id;
  END IF;

  RETURN target_project.uuid;
END;
$$;
