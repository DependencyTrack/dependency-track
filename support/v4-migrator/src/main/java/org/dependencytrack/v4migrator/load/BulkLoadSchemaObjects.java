/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.v4migrator.load;

import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Foreign keys and indexes that {@link LoadPhase} drops before inserting, because PostgreSQL
 * builds and validates them in bulk far faster than it maintains them row by row.
 *
 * <p>Definitions match the Flyway head pinned in {@code Preflight.EXPECTED_FLYWAY_HEAD}, and
 * must be regenerated when it changes. {@code LoadSchemaRestoreIT} fails if they drift.
 * Unique indexes stay in place so that duplicates still fail on insert.
 */
public final class BulkLoadSchemaObjects {

    private static final Logger LOGGER = LoggerFactory.getLogger(BulkLoadSchemaObjects.class);

    private record ForeignKey(String table, String name, String definition) {}

    private record MetricsForeignKey(String table, String name) {}

    private record Index(String name, String definition) {}

    // Dropped but never restored: V202606101343 drops these on the apiserver's first start,
    // so validating them against the metrics tables here would be wasted work.
    private static final List<MetricsForeignKey> METRICS_FOREIGN_KEYS = List.of(
            new MetricsForeignKey("DEPENDENCYMETRICS", "DEPENDENCYMETRICS_COMPONENT_FK"),
            new MetricsForeignKey("DEPENDENCYMETRICS", "DEPENDENCYMETRICS_PROJECT_FK"),
            new MetricsForeignKey("PROJECTMETRICS", "PROJECTMETRICS_PROJECT_FK"));

    private static final List<ForeignKey> FOREIGN_KEYS = List.of(
            new ForeignKey("AFFECTEDVERSIONATTRIBUTION", "AFFECTEDVERSIONATTRIBUTION_VULNERABILITY_FK", """
                FOREIGN KEY ("VULNERABILITY") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("AFFECTEDVERSIONATTRIBUTION", "AFFECTEDVERSIONATTRIBUTION_VULNERABLESOFTWARE_FK", """
                FOREIGN KEY ("VULNERABLE_SOFTWARE") REFERENCES "VULNERABLESOFTWARE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("ANALYSIS", "ANALYSIS_COMPONENT_FK", """
                FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("ANALYSIS", "ANALYSIS_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("ANALYSIS", "ANALYSIS_VULNERABILITY_FK", """
                FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("ANALYSIS", "ANALYSIS_VULNERABILITY_POLICY_ID_FK", """
                FOREIGN KEY ("VULNERABILITY_POLICY_ID") REFERENCES "VULNERABILITY_POLICY"("ID")
                """),
            new ForeignKey("ANALYSISCOMMENT", "ANALYSISCOMMENT_ANALYSIS_FK", """
                FOREIGN KEY ("ANALYSIS_ID") REFERENCES "ANALYSIS"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("APIKEYS_TEAMS", "APIKEYS_TEAMS_APIKEY_FK", """
                FOREIGN KEY ("APIKEY_ID") REFERENCES "APIKEY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("APIKEYS_TEAMS", "APIKEYS_TEAMS_TEAM_FK", """
                FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("BOM", "BOM_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("COMPONENT", "COMPONENT_COMPONENT_FK", """
                FOREIGN KEY ("PARENT_COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("COMPONENT", "COMPONENT_LICENSE_FK", """
                FOREIGN KEY ("LICENSE_ID") REFERENCES "LICENSE"("ID") DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("COMPONENT", "COMPONENT_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("COMPONENTS_VULNERABILITIES", "COMPONENTS_VULNERABILITIES_COMPONENT_FK", """
                FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("COMPONENTS_VULNERABILITIES", "COMPONENTS_VULNERABILITIES_VULNERABILITY_FK", """
                FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("COMPONENT_PROPERTY", "COMPONENT_PROPERTY_COMPONENT_ID_FK", """
                FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("FINDINGATTRIBUTION", "FINDINGATTRIBUTION_COMPONENT_FK", """
                FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("FINDINGATTRIBUTION", "FINDINGATTRIBUTION_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("FINDINGATTRIBUTION", "FINDINGATTRIBUTION_VULNERABILITY_FK", """
                FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("LICENSEGROUP_LICENSE", "LICENSEGROUP_LICENSE_LICENSEGROUP_FK", """
                FOREIGN KEY ("LICENSEGROUP_ID") REFERENCES "LICENSEGROUP"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("LICENSEGROUP_LICENSE", "LICENSEGROUP_LICENSE_LICENSE_FK", """
                FOREIGN KEY ("LICENSE_ID") REFERENCES "LICENSE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("MAPPEDLDAPGROUP", "MAPPEDLDAPGROUP_TEAM_FK", """
                FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("MAPPEDOIDCGROUP", "MAPPEDOIDCGROUP_OIDCGROUP_FK", """
                FOREIGN KEY ("GROUP_ID") REFERENCES "OIDCGROUP"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("MAPPEDOIDCGROUP", "MAPPEDOIDCGROUP_TEAM_FK", """
                FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("NOTIFICATIONRULE", "NOTIFICATIONRULE_NOTIFICATIONPUBLISHER_FK", """
                FOREIGN KEY ("PUBLISHER") REFERENCES "NOTIFICATIONPUBLISHER"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("NOTIFICATIONRULE_PROJECTS", "NOTIFICATIONRULE_PROJECTS_NOTIFICATIONRULE_FK", """
                FOREIGN KEY ("NOTIFICATIONRULE_ID") REFERENCES "NOTIFICATIONRULE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("NOTIFICATIONRULE_PROJECTS", "NOTIFICATIONRULE_PROJECTS_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("NOTIFICATIONRULE_TAGS", "NOTIFICATIONRULE_TAGS_NOTIFICATIONRULE_FK", """
                FOREIGN KEY ("NOTIFICATIONRULE_ID") REFERENCES "NOTIFICATIONRULE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("NOTIFICATIONRULE_TAGS", "NOTIFICATIONRULE_TAGS_TAG_FK", """
                FOREIGN KEY ("TAG_ID") REFERENCES "TAG"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("NOTIFICATIONRULE_TEAMS", "NOTIFICATIONRULE_TEAMS_NOTIFICATIONRULE_FK", """
                FOREIGN KEY ("NOTIFICATIONRULE_ID") REFERENCES "NOTIFICATIONRULE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("NOTIFICATIONRULE_TEAMS", "NOTIFICATIONRULE_TEAMS_TEAM_FK", """
                FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("POLICYCONDITION", "POLICYCONDITION_POLICY_FK", """
                FOREIGN KEY ("POLICY_ID") REFERENCES "POLICY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("POLICYVIOLATION", "POLICYVIOLATION_COMPONENT_FK", """
                FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("POLICYVIOLATION", "POLICYVIOLATION_POLICYCONDITION_FK", """
                FOREIGN KEY ("POLICYCONDITION_ID") REFERENCES "POLICYCONDITION"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("POLICYVIOLATION", "POLICYVIOLATION_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("POLICY_PROJECTS", "POLICY_PROJECTS_POLICY_FK", """
                FOREIGN KEY ("POLICY_ID") REFERENCES "POLICY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("POLICY_PROJECTS", "POLICY_PROJECTS_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("POLICY_TAGS", "POLICY_TAGS_POLICY_FK", """
                FOREIGN KEY ("POLICY_ID") REFERENCES "POLICY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("POLICY_TAGS", "POLICY_TAGS_TAG_FK", """
                FOREIGN KEY ("TAG_ID") REFERENCES "TAG"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("PROJECT", "PROJECT_COLLECTION_TAG_FK", """
                FOREIGN KEY ("COLLECTION_TAG_ID") REFERENCES "TAG"("ID") ON DELETE RESTRICT
                """),
            new ForeignKey("PROJECT", "PROJECT_PROJECT_FK", """
                FOREIGN KEY ("PARENT_PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("PROJECTS_TAGS", "PROJECTS_TAGS_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("PROJECTS_TAGS", "PROJECTS_TAGS_TAG_FK", """
                FOREIGN KEY ("TAG_ID") REFERENCES "TAG"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("PROJECT_ACCESS_TEAMS", "PROJECT_ACCESS_TEAMS_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("PROJECT_ACCESS_TEAMS", "PROJECT_ACCESS_TEAMS_TEAM_FK", """
                FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("PROJECT_ACCESS_USERS", "PROJECT_ACCESS_USERS_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE
                """),
            new ForeignKey("PROJECT_ACCESS_USERS", "PROJECT_ACCESS_USERS_USER_FK", """
                FOREIGN KEY ("USER_ID") REFERENCES "USER"("ID") ON DELETE CASCADE
                """),
            new ForeignKey("PROJECT_HIERARCHY", "PROJECT_HIERARCHY_CHILD_PROJECT_FK", """
                FOREIGN KEY ("CHILD_PROJECT_ID") REFERENCES "PROJECT"("ID") DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("PROJECT_HIERARCHY", "PROJECT_HIERARCHY_PARENT_PROJECT_FK", """
                FOREIGN KEY ("PARENT_PROJECT_ID") REFERENCES "PROJECT"("ID") DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("PROJECT_METADATA", "PROJECT_METADATA_PROJECT_ID_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("PROJECT_PROPERTY", "PROJECT_PROPERTY_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("SERVICECOMPONENT", "SERVICECOMPONENT_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("SERVICECOMPONENT", "SERVICECOMPONENT_SERVICECOMPONENT_FK", """
                FOREIGN KEY ("PARENT_SERVICECOMPONENT_ID") REFERENCES "SERVICECOMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey(
                    "SERVICECOMPONENTS_VULNERABILITIES", "SERVICECOMPONENTS_VULNERABILITIES_SERVICECOMPONENT_FK", """
                FOREIGN KEY ("SERVICECOMPONENT_ID") REFERENCES "SERVICECOMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey(
                    "SERVICECOMPONENTS_VULNERABILITIES", "SERVICECOMPONENTS_VULNERABILITIES_VULNERABILITY_FK", """
                FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("TEAMS_PERMISSIONS", "TEAMS_PERMISSIONS_PERMISSION_FK", """
                FOREIGN KEY ("PERMISSION_ID") REFERENCES "PERMISSION"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("TEAMS_PERMISSIONS", "TEAMS_PERMISSIONS_TEAM_FK", """
                FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("USERS_PERMISSIONS", "USERS_PERMISSIONS_PERMISSION_FK", """
                FOREIGN KEY ("PERMISSION_ID") REFERENCES "PERMISSION"("ID") ON DELETE CASCADE
                """),
            new ForeignKey("USERS_PERMISSIONS", "USERS_PERMISSIONS_USER_FK", """
                FOREIGN KEY ("USER_ID") REFERENCES "USER"("ID") ON DELETE CASCADE
                """),
            new ForeignKey("USERS_TEAMS", "USERS_TEAMS_TEAM_FK", """
                FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE
                """),
            new ForeignKey("USERS_TEAMS", "USERS_TEAMS_USER_FK", """
                FOREIGN KEY ("USER_ID") REFERENCES "USER"("ID") ON DELETE CASCADE
                """),
            new ForeignKey("VEX", "VEX_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("VIOLATIONANALYSIS", "VIOLATIONANALYSIS_COMPONENT_FK", """
                FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("VIOLATIONANALYSIS", "VIOLATIONANALYSIS_POLICYVIOLATION_FK", """
                FOREIGN KEY ("POLICYVIOLATION_ID") REFERENCES "POLICYVIOLATION"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("VIOLATIONANALYSIS", "VIOLATIONANALYSIS_PROJECT_FK", """
                FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey("VIOLATIONANALYSISCOMMENT", "VIOLATIONANALYSISCOMMENT_VIOLATIONANALYSIS_FK", """
                FOREIGN KEY ("VIOLATIONANALYSIS_ID") REFERENCES "VIOLATIONANALYSIS"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey(
                    "VULNERABLESOFTWARE_VULNERABILITIES", "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABILITY_FK", """
                FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """),
            new ForeignKey(
                    "VULNERABLESOFTWARE_VULNERABILITIES",
                    "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABLESOFTWARE_FK",
                    """
                FOREIGN KEY ("VULNERABLESOFTWARE_ID") REFERENCES "VULNERABLESOFTWARE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                """));

    private static final List<Index> INDEXES = List.of(
            new Index("AFFECTEDVERSIONATTRIBUTION_KEYS_IDX", """
                CREATE INDEX "AFFECTEDVERSIONATTRIBUTION_KEYS_IDX" ON "AFFECTEDVERSIONATTRIBUTION" USING btree ("VULNERABILITY", "VULNERABLE_SOFTWARE")
                """),
            new Index("ANALYSIS_COMPONENT_ID_IDX", """
                CREATE INDEX "ANALYSIS_COMPONENT_ID_IDX" ON "ANALYSIS" USING btree ("COMPONENT_ID")
                """),
            new Index("ANALYSIS_VULNERABILITY_ID_IDX", """
                CREATE INDEX "ANALYSIS_VULNERABILITY_ID_IDX" ON "ANALYSIS" USING btree ("VULNERABILITY_ID")
                """),
            new Index("ANALYSISCOMMENT_ANALYSIS_ID_IDX", """
                CREATE INDEX "ANALYSISCOMMENT_ANALYSIS_ID_IDX" ON "ANALYSISCOMMENT" USING btree ("ANALYSIS_ID")
                """),
            new Index("BOM_PROJECT_ID_IDX", """
                CREATE INDEX "BOM_PROJECT_ID_IDX" ON "BOM" USING btree ("PROJECT_ID")
                """),
            new Index("COMPONENT_BLAKE2B_256_IDX", """
                CREATE INDEX "COMPONENT_BLAKE2B_256_IDX" ON "COMPONENT" USING btree ("BLAKE2B_256") WHERE ("BLAKE2B_256" IS NOT NULL)
                """),
            new Index("COMPONENT_BLAKE2B_384_IDX", """
                CREATE INDEX "COMPONENT_BLAKE2B_384_IDX" ON "COMPONENT" USING btree ("BLAKE2B_384") WHERE ("BLAKE2B_384" IS NOT NULL)
                """),
            new Index("COMPONENT_BLAKE2B_512_IDX", """
                CREATE INDEX "COMPONENT_BLAKE2B_512_IDX" ON "COMPONENT" USING btree ("BLAKE2B_512") WHERE ("BLAKE2B_512" IS NOT NULL)
                """),
            new Index("COMPONENT_BLAKE3_IDX", """
                CREATE INDEX "COMPONENT_BLAKE3_IDX" ON "COMPONENT" USING btree ("BLAKE3") WHERE ("BLAKE3" IS NOT NULL)
                """),
            new Index("COMPONENT_CLASSIFIER_IDX", """
                CREATE INDEX "COMPONENT_CLASSIFIER_IDX" ON "COMPONENT" USING btree ("CLASSIFIER")
                """),
            new Index("COMPONENT_COORDINATES_SEARCH_IDX", """
                CREATE INDEX "COMPONENT_COORDINATES_SEARCH_IDX" ON "COMPONENT" USING gin (lower(("NAME")::text) gin_trgm_ops, lower(("VERSION")::text) gin_trgm_ops, lower(("GROUP")::text) gin_trgm_ops)
                """),
            new Index("COMPONENT_CPE_IDX", """
                CREATE INDEX "COMPONENT_CPE_IDX" ON "COMPONENT" USING btree ("CPE")
                """),
            new Index("COMPONENT_DIRECT_DEPENDENCIES_JSONB_IDX", """
                CREATE INDEX "COMPONENT_DIRECT_DEPENDENCIES_JSONB_IDX" ON "COMPONENT" USING gin ("DIRECT_DEPENDENCIES" jsonb_path_ops)
                """),
            new Index("COMPONENT_GROUP_IDX", """
                CREATE INDEX "COMPONENT_GROUP_IDX" ON "COMPONENT" USING btree ("GROUP")
                """),
            new Index("COMPONENT_LAST_RISKSCORE_IDX", """
                CREATE INDEX "COMPONENT_LAST_RISKSCORE_IDX" ON "COMPONENT" USING btree ("LAST_RISKSCORE")
                """),
            new Index("COMPONENT_LICENSE_ID_IDX", """
                CREATE INDEX "COMPONENT_LICENSE_ID_IDX" ON "COMPONENT" USING btree ("LICENSE_ID")
                """),
            new Index("COMPONENT_MD5_IDX", """
                CREATE INDEX "COMPONENT_MD5_IDX" ON "COMPONENT" USING btree ("MD5") WHERE ("MD5" IS NOT NULL)
                """),
            new Index("COMPONENT_NAME_IDX", """
                CREATE INDEX "COMPONENT_NAME_IDX" ON "COMPONENT" USING btree ("NAME")
                """),
            new Index("COMPONENT_PARENT_COMPONENT_ID_IDX", """
                CREATE INDEX "COMPONENT_PARENT_COMPONENT_ID_IDX" ON "COMPONENT" USING btree ("PARENT_COMPONENT_ID")
                """),
            new Index("COMPONENT_PROJECT_ID_IDX", """
                CREATE INDEX "COMPONENT_PROJECT_ID_IDX" ON "COMPONENT" USING btree ("PROJECT_ID")
                """),
            new Index("COMPONENT_PURL_COORDINATES_IDX", """
                CREATE INDEX "COMPONENT_PURL_COORDINATES_IDX" ON "COMPONENT" USING btree ("PURLCOORDINATES")
                """),
            new Index("COMPONENT_PURL_IDX", """
                CREATE INDEX "COMPONENT_PURL_IDX" ON "COMPONENT" USING btree ("PURL")
                """),
            new Index("COMPONENT_PURL_SEARCH_IDX", """
                CREATE INDEX "COMPONENT_PURL_SEARCH_IDX" ON "COMPONENT" USING btree (lower(("PURL")::text) text_pattern_ops) WHERE ("PURL" IS NOT NULL)
                """),
            new Index("COMPONENT_SHA1_IDX", """
                CREATE INDEX "COMPONENT_SHA1_IDX" ON "COMPONENT" USING btree ("SHA1") WHERE ("SHA1" IS NOT NULL)
                """),
            new Index("COMPONENT_SHA3_256_IDX", """
                CREATE INDEX "COMPONENT_SHA3_256_IDX" ON "COMPONENT" USING btree ("SHA3_256") WHERE ("SHA3_256" IS NOT NULL)
                """),
            new Index("COMPONENT_SHA3_384_IDX", """
                CREATE INDEX "COMPONENT_SHA3_384_IDX" ON "COMPONENT" USING btree ("SHA3_384") WHERE ("SHA3_384" IS NOT NULL)
                """),
            new Index("COMPONENT_SHA3_512_IDX", """
                CREATE INDEX "COMPONENT_SHA3_512_IDX" ON "COMPONENT" USING btree ("SHA3_512") WHERE ("SHA3_512" IS NOT NULL)
                """),
            new Index("COMPONENT_SHA_256_IDX", """
                CREATE INDEX "COMPONENT_SHA_256_IDX" ON "COMPONENT" USING btree ("SHA_256") WHERE ("SHA_256" IS NOT NULL)
                """),
            new Index("COMPONENT_SHA_384_IDX", """
                CREATE INDEX "COMPONENT_SHA_384_IDX" ON "COMPONENT" USING btree ("SHA_384") WHERE ("SHA_384" IS NOT NULL)
                """),
            new Index("COMPONENT_SHA_512_IDX", """
                CREATE INDEX "COMPONENT_SHA_512_IDX" ON "COMPONENT" USING btree ("SHA_512") WHERE ("SHA_512" IS NOT NULL)
                """),
            new Index("COMPONENT_SWID_TAGID_IDX", """
                CREATE INDEX "COMPONENT_SWID_TAGID_IDX" ON "COMPONENT" USING btree ("SWIDTAGID")
                """),
            new Index("COMPONENTS_VULNERABILITIES_VULNERABILITY_ID_IDX", """
                CREATE INDEX "COMPONENTS_VULNERABILITIES_VULNERABILITY_ID_IDX" ON "COMPONENTS_VULNERABILITIES" USING btree ("VULNERABILITY_ID")
                """),
            new Index("COMPONENT_PROPERTY_COMPONENT_ID_IDX", """
                CREATE INDEX "COMPONENT_PROPERTY_COMPONENT_ID_IDX" ON "COMPONENT_PROPERTY" USING btree ("COMPONENT_ID")
                """),
            new Index("FINDINGATTRIBUTION_COMPONENT_VULN_IDX", """
                CREATE INDEX "FINDINGATTRIBUTION_COMPONENT_VULN_IDX" ON "FINDINGATTRIBUTION" USING btree ("COMPONENT_ID", "VULNERABILITY_ID", "DELETED_AT" DESC, "ID")
                """),
            new Index("FINDINGATTRIBUTION_PROJECT_ID_IDX", """
                CREATE INDEX "FINDINGATTRIBUTION_PROJECT_ID_IDX" ON "FINDINGATTRIBUTION" USING btree ("PROJECT_ID")
                """),
            new Index("FINDINGATTRIBUTION_VULNERABILITY_ID_IDX", """
                CREATE INDEX "FINDINGATTRIBUTION_VULNERABILITY_ID_IDX" ON "FINDINGATTRIBUTION" USING btree ("VULNERABILITY_ID")
                """),
            new Index("LICENSE_NAME_IDX", """
                CREATE INDEX "LICENSE_NAME_IDX" ON "LICENSE" USING btree ("NAME")
                """),
            new Index("LICENSEGROUP_NAME_IDX", """
                CREATE INDEX "LICENSEGROUP_NAME_IDX" ON "LICENSEGROUP" USING btree ("NAME")
                """),
            new Index("LICENSEGROUP_LICENSE_LICENSEGROUP_ID_IDX", """
                CREATE INDEX "LICENSEGROUP_LICENSE_LICENSEGROUP_ID_IDX" ON "LICENSEGROUP_LICENSE" USING btree ("LICENSEGROUP_ID")
                """),
            new Index("LICENSEGROUP_LICENSE_LICENSE_ID_IDX", """
                CREATE INDEX "LICENSEGROUP_LICENSE_LICENSE_ID_IDX" ON "LICENSEGROUP_LICENSE" USING btree ("LICENSE_ID")
                """),
            new Index("MAPPEDOIDCGROUP_GROUP_ID_IDX", """
                CREATE INDEX "MAPPEDOIDCGROUP_GROUP_ID_IDX" ON "MAPPEDOIDCGROUP" USING btree ("GROUP_ID")
                """),
            new Index("NOTIFICATIONRULE_PUBLISHER_IDX", """
                CREATE INDEX "NOTIFICATIONRULE_PUBLISHER_IDX" ON "NOTIFICATIONRULE" USING btree ("PUBLISHER")
                """),
            new Index("NOTIFICATIONRULE_PROJECTS_NOTIFICATIONRULE_ID_IDX", """
                CREATE INDEX "NOTIFICATIONRULE_PROJECTS_NOTIFICATIONRULE_ID_IDX" ON "NOTIFICATIONRULE_PROJECTS" USING btree ("NOTIFICATIONRULE_ID")
                """),
            new Index("NOTIFICATIONRULE_PROJECTS_PROJECT_ID_IDX", """
                CREATE INDEX "NOTIFICATIONRULE_PROJECTS_PROJECT_ID_IDX" ON "NOTIFICATIONRULE_PROJECTS" USING btree ("PROJECT_ID")
                """),
            new Index("PACKAGE_METADATA_RESOLVED_AT_IDX", """
                CREATE INDEX "PACKAGE_METADATA_RESOLVED_AT_IDX" ON "PACKAGE_METADATA" USING btree ("RESOLVED_AT")
                """),
            new Index("POLICY_NAME_IDX", """
                CREATE INDEX "POLICY_NAME_IDX" ON "POLICY" USING btree ("NAME")
                """),
            new Index("POLICYCONDITION_POLICY_ID_IDX", """
                CREATE INDEX "POLICYCONDITION_POLICY_ID_IDX" ON "POLICYCONDITION" USING btree ("POLICY_ID")
                """),
            new Index("POLICYVIOLATION_POLICYCONDITION_ID_IDX", """
                CREATE INDEX "POLICYVIOLATION_POLICYCONDITION_ID_IDX" ON "POLICYVIOLATION" USING btree ("POLICYCONDITION_ID")
                """),
            new Index("POLICYVIOLATION_PROJECT_IDX", """
                CREATE INDEX "POLICYVIOLATION_PROJECT_IDX" ON "POLICYVIOLATION" USING btree ("PROJECT_ID")
                """),
            new Index("POLICY_PROJECTS_POLICY_ID_IDX", """
                CREATE INDEX "POLICY_PROJECTS_POLICY_ID_IDX" ON "POLICY_PROJECTS" USING btree ("POLICY_ID")
                """),
            new Index("POLICY_PROJECTS_PROJECT_ID_IDX", """
                CREATE INDEX "POLICY_PROJECTS_PROJECT_ID_IDX" ON "POLICY_PROJECTS" USING btree ("PROJECT_ID")
                """),
            new Index("PROJECT_CLASSIFIER_IDX", """
                CREATE INDEX "PROJECT_CLASSIFIER_IDX" ON "PROJECT" USING btree ("CLASSIFIER")
                """),
            new Index("PROJECT_COLLECTION_TAG_ID_IDX", """
                CREATE INDEX "PROJECT_COLLECTION_TAG_ID_IDX" ON "PROJECT" USING btree ("COLLECTION_TAG_ID") WHERE ("COLLECTION_TAG_ID" IS NOT NULL)
                """),
            new Index("PROJECT_CPE_IDX", """
                CREATE INDEX "PROJECT_CPE_IDX" ON "PROJECT" USING btree ("CPE")
                """),
            new Index("PROJECT_GROUP_IDX", """
                CREATE INDEX "PROJECT_GROUP_IDX" ON "PROJECT" USING btree ("GROUP")
                """),
            new Index("PROJECT_INACTIVE_SINCE_IDX", """
                CREATE INDEX "PROJECT_INACTIVE_SINCE_IDX" ON "PROJECT" USING btree ("INACTIVE_SINCE")
                """),
            new Index("PROJECT_LASTBOMIMPORT_FORMAT_IDX", """
                CREATE INDEX "PROJECT_LASTBOMIMPORT_FORMAT_IDX" ON "PROJECT" USING btree ("LAST_BOM_IMPORTED_FORMAT")
                """),
            new Index("PROJECT_LASTBOMIMPORT_IDX", """
                CREATE INDEX "PROJECT_LASTBOMIMPORT_IDX" ON "PROJECT" USING btree ("LAST_BOM_IMPORTED")
                """),
            new Index("PROJECT_LAST_RISKSCORE_IDX", """
                CREATE INDEX "PROJECT_LAST_RISKSCORE_IDX" ON "PROJECT" USING btree ("LAST_RISKSCORE")
                """),
            new Index("PROJECT_NAME_IDX", """
                CREATE INDEX "PROJECT_NAME_IDX" ON "PROJECT" USING btree ("NAME")
                """),
            new Index("PROJECT_PARENT_PROJECT_ID_IDX", """
                CREATE INDEX "PROJECT_PARENT_PROJECT_ID_IDX" ON "PROJECT" USING btree ("PARENT_PROJECT_ID")
                """),
            new Index("PROJECT_PURL_IDX", """
                CREATE INDEX "PROJECT_PURL_IDX" ON "PROJECT" USING btree ("PURL")
                """),
            new Index("PROJECT_SWID_TAGID_IDX", """
                CREATE INDEX "PROJECT_SWID_TAGID_IDX" ON "PROJECT" USING btree ("SWIDTAGID")
                """),
            new Index("PROJECT_VERSION_IDX", """
                CREATE INDEX "PROJECT_VERSION_IDX" ON "PROJECT" USING btree ("VERSION")
                """),
            new Index("PROJECT_ACCESS_TEAMS_TEAM_IDX", """
                CREATE INDEX "PROJECT_ACCESS_TEAMS_TEAM_IDX" ON "PROJECT_ACCESS_TEAMS" USING btree ("TEAM_ID")
                """),
            new Index("PROJECT_ACCESS_USERS_USER_IDX", """
                CREATE INDEX "PROJECT_ACCESS_USERS_USER_IDX" ON "PROJECT_ACCESS_USERS" USING btree ("USER_ID")
                """),
            new Index("REPOSITORY_UUID_IDX", """
                CREATE INDEX "REPOSITORY_UUID_IDX" ON "REPOSITORY" USING btree ("UUID")
                """),
            new Index("SERVICECOMPONENT_LAST_RISKSCORE_IDX", """
                CREATE INDEX "SERVICECOMPONENT_LAST_RISKSCORE_IDX" ON "SERVICECOMPONENT" USING btree ("LAST_RISKSCORE")
                """),
            new Index("SERVICECOMPONENT_PARENT_SERVICECOMPONENT_ID_IDX", """
                CREATE INDEX "SERVICECOMPONENT_PARENT_SERVICECOMPONENT_ID_IDX" ON "SERVICECOMPONENT" USING btree ("PARENT_SERVICECOMPONENT_ID")
                """),
            new Index("SERVICECOMPONENT_PROJECT_ID_IDX", """
                CREATE INDEX "SERVICECOMPONENT_PROJECT_ID_IDX" ON "SERVICECOMPONENT" USING btree ("PROJECT_ID")
                """),
            new Index("SERVICECOMPONENTS_VULNERABILITIES_SERVICECOMPONENT_ID_IDX", """
                CREATE INDEX "SERVICECOMPONENTS_VULNERABILITIES_SERVICECOMPONENT_ID_IDX" ON "SERVICECOMPONENTS_VULNERABILITIES" USING btree ("SERVICECOMPONENT_ID")
                """),
            new Index("SERVICECOMPONENTS_VULNERABILITIES_VULNERABILITY_ID_IDX", """
                CREATE INDEX "SERVICECOMPONENTS_VULNERABILITIES_VULNERABILITY_ID_IDX" ON "SERVICECOMPONENTS_VULNERABILITIES" USING btree ("VULNERABILITY_ID")
                """),
            new Index("USERS_TEAMS_TEAM_IDX", """
                CREATE INDEX "USERS_TEAMS_TEAM_IDX" ON "USERS_TEAMS" USING btree ("TEAM_ID")
                """),
            new Index("VEX_PROJECT_ID_IDX", """
                CREATE INDEX "VEX_PROJECT_ID_IDX" ON "VEX" USING btree ("PROJECT_ID")
                """),
            new Index("VIOLATIONANALYSIS_COMPONENT_ID_IDX", """
                CREATE INDEX "VIOLATIONANALYSIS_COMPONENT_ID_IDX" ON "VIOLATIONANALYSIS" USING btree ("COMPONENT_ID")
                """),
            new Index("VIOLATIONANALYSIS_POLICYVIOLATION_ID_IDX", """
                CREATE INDEX "VIOLATIONANALYSIS_POLICYVIOLATION_ID_IDX" ON "VIOLATIONANALYSIS" USING btree ("POLICYVIOLATION_ID")
                """),
            new Index("VIOLATIONANALYSISCOMMENT_VIOLATIONANALYSIS_ID_IDX", """
                CREATE INDEX "VIOLATIONANALYSISCOMMENT_VIOLATIONANALYSIS_ID_IDX" ON "VIOLATIONANALYSISCOMMENT" USING btree ("VIOLATIONANALYSIS_ID")
                """),
            new Index("VULNERABILITY_CREATED_IDX", """
                CREATE INDEX "VULNERABILITY_CREATED_IDX" ON "VULNERABILITY" USING btree ("CREATED")
                """),
            new Index("VULNERABILITY_PUBLISHED_IDX", """
                CREATE INDEX "VULNERABILITY_PUBLISHED_IDX" ON "VULNERABILITY" USING btree ("PUBLISHED")
                """),
            new Index("VULNERABILITY_UPDATED_IDX", """
                CREATE INDEX "VULNERABILITY_UPDATED_IDX" ON "VULNERABILITY" USING btree ("UPDATED")
                """),
            new Index("VULNERABILITY_ALIAS_GROUP_IDX", """
                CREATE INDEX "VULNERABILITY_ALIAS_GROUP_IDX" ON "VULNERABILITY_ALIAS" USING btree ("GROUP_ID")
                """),
            new Index("VULN_ALIAS_ASSERTION_ALIAS_IDX", """
                CREATE INDEX "VULN_ALIAS_ASSERTION_ALIAS_IDX" ON "VULNERABILITY_ALIAS_ASSERTION" USING btree ("ALIAS_SOURCE", "ALIAS_ID")
                """),
            new Index("VULN_ALIAS_ASSERTION_VULN_IDX", """
                CREATE INDEX "VULN_ALIAS_ASSERTION_VULN_IDX" ON "VULNERABILITY_ALIAS_ASSERTION" USING btree ("VULN_SOURCE", "VULN_ID")
                """),
            new Index("VULNERABLESOFTWARE_CPE23_VERSION_RANGE_IDX", """
                CREATE INDEX "VULNERABLESOFTWARE_CPE23_VERSION_RANGE_IDX" ON "VULNERABLESOFTWARE" USING btree ("CPE23", "VERSIONENDEXCLUDING", "VERSIONENDINCLUDING", "VERSIONSTARTEXCLUDING", "VERSIONSTARTINCLUDING")
                """),
            new Index("VULNERABLESOFTWARE_FULL_PURL_IDX", """
                CREATE INDEX "VULNERABLESOFTWARE_FULL_PURL_IDX" ON "VULNERABLESOFTWARE" USING btree ("PURL_TYPE", "PURL_NAMESPACE", "PURL_NAME", "VERSION") WHERE ("PURL_TYPE" IS NOT NULL)
                """),
            new Index("VULNERABLESOFTWARE_VULNERABILITIES_VULNERABILITY_ID_IDX", """
                CREATE INDEX "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABILITY_ID_IDX" ON "VULNERABLESOFTWARE_VULNERABILITIES" USING btree ("VULNERABILITY_ID")
                """),
            new Index("VULNERABLESOFTWARE_VULNERABILITIES_VULNERABLESOFTWARE_ID_IDX", """
                CREATE INDEX "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABLESOFTWARE_ID_IDX" ON "VULNERABLESOFTWARE_VULNERABILITIES" USING btree ("VULNERABLESOFTWARE_ID")
                """));

    private BulkLoadSchemaObjects() {}

    public static String recoveryInstructions(final String stagingSchema) {
        return """
                This database is incomplete: foreign keys and indexes may be missing, triggers may be disabled, \
                and tables may hold partial data. Do not use it, and do not delete rows to retry. \
                To retry, drop the v5 schema but keep staging schema '%s', then run 'bootstrap' and 'load'. \
                Extract and transform do not need to be repeated.""".formatted(stagingSchema);
    }

    /**
     * Atomic, so that {@link #findMissing(Jdbi)} can tell a target that never started a load
     * from one that did.
     */
    static void dropAll(final Jdbi jdbi) {
        LOGGER.info(
                "Dropping {} foreign key(s) and {} index(es) for the duration of the load",
                METRICS_FOREIGN_KEYS.size() + FOREIGN_KEYS.size(),
                INDEXES.size());
        jdbi.useTransaction(h -> {
            for (final MetricsForeignKey fk : METRICS_FOREIGN_KEYS) {
                h.execute("ALTER TABLE \"%s\" DROP CONSTRAINT IF EXISTS \"%s\"".formatted(fk.table(), fk.name()));
            }
            for (final ForeignKey fk : FOREIGN_KEYS) {
                h.execute("ALTER TABLE \"%s\" DROP CONSTRAINT IF EXISTS \"%s\"".formatted(fk.table(), fk.name()));
            }
            for (final Index index : INDEXES) {
                h.execute("DROP INDEX IF EXISTS \"%s\"".formatted(index.name()));
            }
        });
    }

    static void restoreIndexes(final Jdbi jdbi) {
        LOGGER.info("Rebuilding {} index(es)", INDEXES.size());
        jdbi.useHandle(h -> {
            for (final Index index : INDEXES) {
                LOGGER.info("Rebuilding index {}", index.name());
                h.execute(index.definition());
            }
        });
    }

    static void restoreForeignKeys(final Jdbi jdbi) {
        LOGGER.info("Re-adding and validating {} foreign key(s)", FOREIGN_KEYS.size());
        jdbi.useHandle(h -> {
            for (final ForeignKey fk : FOREIGN_KEYS) {
                LOGGER.info("Re-adding foreign key {}", fk.name());
                h.execute("ALTER TABLE \"%s\" ADD CONSTRAINT \"%s\" %s"
                        .formatted(fk.table(), fk.name(), fk.definition()));
            }
        });
    }

    /**
     * Names of restorable objects absent from the target. Anything returned here means that a
     * load started on this schema and did not finish.
     */
    public static List<String> findMissing(final Jdbi jdbi) {
        final Set<String> present = new HashSet<>();
        jdbi.useHandle(h -> {
            present.addAll(h.createQuery("""
                    SELECT conname
                      FROM pg_constraint
                     WHERE contype = 'f'
                       AND connamespace = current_schema()::regnamespace
                    """).mapTo(String.class).list());
            present.addAll(h.createQuery("""
                    SELECT relname
                      FROM pg_class
                     WHERE relkind = 'i'
                       AND relnamespace = current_schema()::regnamespace
                    """).mapTo(String.class).list());
        });

        final List<String> missing = new ArrayList<>();
        FOREIGN_KEYS.stream()
                .map(ForeignKey::name)
                .filter(it -> !present.contains(it))
                .forEach(missing::add);
        INDEXES.stream().map(Index::name).filter(it -> !present.contains(it)).forEach(missing::add);
        return List.copyOf(missing);
    }
}
