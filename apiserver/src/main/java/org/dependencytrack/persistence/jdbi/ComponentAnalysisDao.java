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
package org.dependencytrack.persistence.jdbi;

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Access to durable, identity-keyed component analyses (license curation).
 * <p>
 * Component records are deleted and recreated across BOM uploads; a component
 * analysis is therefore keyed by the component's identity (purl, or
 * group/name/version) within a project, and re-applied on every ingest by
 * {@code ImportBomActivity}.
 */
public final class ComponentAnalysisDao {

    private final Handle handle;

    public ComponentAnalysisDao(final Handle handle) {
        this.handle = handle;
    }

    public record ComponentAnalysis(
            long id,
            long projectId,
            @Nullable String purl,
            @Nullable String group,
            String name,
            @Nullable String version,
            @Nullable Long licenseId,
            @Nullable Long declaredLicenseId,
            @Nullable String declaredLicenseName,
            @Nullable String declaredLicenseExpression,
            @Nullable String details,
            @Nullable Long policyId) {
    }

    public record ComponentAnalysisComment(
            long id,
            Instant timestamp,
            @Nullable String commenter,
            String comment) {
    }

    private static final RowMapper<ComponentAnalysis> ANALYSIS_ROW_MAPPER = (rs, ctx) -> new ComponentAnalysis(
            rs.getLong("ID"),
            rs.getLong("PROJECT_ID"),
            rs.getString("PURL"),
            rs.getString("GROUP"),
            rs.getString("NAME"),
            rs.getString("VERSION"),
            rs.getObject("LICENSE_ID", Long.class),
            rs.getObject("DECLARED_LICENSE_ID", Long.class),
            rs.getString("DECLARED_LICENSE_NAME"),
            rs.getString("DECLARED_LICENSE_EXPRESSION"),
            rs.getString("DETAILS"),
            rs.getObject("POLICY_ID", Long.class));

    private static final RowMapper<ComponentAnalysisComment> COMMENT_ROW_MAPPER = (rs, ctx) -> new ComponentAnalysisComment(
            rs.getLong("ID"),
            rs.getTimestamp("TIMESTAMP").toInstant(),
            rs.getString("COMMENTER"),
            rs.getString("COMMENT"));

    /**
     * All analyses of one project, for bulk matching during BOM ingest.
     */
    public List<ComponentAnalysis> getAllByProject(final long projectId) {
        return handle.createQuery("""
                        SELECT "ID", "PROJECT_ID", "PURL", "GROUP", "NAME", "VERSION",
                               "LICENSE_ID", "DECLARED_LICENSE_ID", "DECLARED_LICENSE_NAME",
                               "DECLARED_LICENSE_EXPRESSION", "DETAILS", "POLICY_ID"
                          FROM "COMPONENT_ANALYSIS"
                         WHERE "PROJECT_ID" = :projectId
                        """)
                .bind("projectId", projectId)
                .map(ANALYSIS_ROW_MAPPER)
                .list();
    }

    public Optional<ComponentAnalysis> getByIdentity(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version) {
        return handle.createQuery("""
                        SELECT "ID", "PROJECT_ID", "PURL", "GROUP", "NAME", "VERSION",
                               "LICENSE_ID", "DECLARED_LICENSE_ID", "DECLARED_LICENSE_NAME",
                               "DECLARED_LICENSE_EXPRESSION", "DETAILS", "POLICY_ID"
                          FROM "COMPONENT_ANALYSIS"
                         WHERE "PROJECT_ID" = :projectId
                           AND COALESCE("PURL", '') = COALESCE(:purl, '')
                           AND COALESCE("GROUP", '') = COALESCE(:group, '')
                           AND "NAME" = :name
                           AND COALESCE("VERSION", '') = COALESCE(:version, '')
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .map(ANALYSIS_ROW_MAPPER)
                .findOne();
    }

    /**
     * Create-or-update keyed by the identity unique index; returns the row id.
     */
    public long upsert(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version,
            @Nullable final Long licenseId,
            @Nullable final String details) {
        return handle.createQuery("""
                        INSERT INTO "COMPONENT_ANALYSIS"
                          ("PROJECT_ID", "PURL", "GROUP", "NAME", "VERSION",
                           "LICENSE_ID", "DETAILS")
                        VALUES
                          (:projectId, :purl, :group, :name, :version,
                           :licenseId, :details)
                        ON CONFLICT ("PROJECT_ID", COALESCE("PURL", ''), COALESCE("GROUP", ''),
                                     "NAME", COALESCE("VERSION", ''))
                        DO UPDATE
                           SET "LICENSE_ID" = EXCLUDED."LICENSE_ID"
                             , "DETAILS" = EXCLUDED."DETAILS"
                             , "POLICY_ID" = NULL
                             , "UPDATED_AT" = NOW()
                        RETURNING "ID"
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .bind("licenseId", licenseId)
                .bind("details", details)
                .mapTo(Long.class)
                .one();
    }

    /**
     * Applies an analysis to the project's currently matching component rows
     * (the ingest hook does the same on every later BOM upload). Details are
     * written to the component notes; a license override also clears a
     * BOM-declared multi-license expression.
     */
    public int applyToComponents(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version,
            @Nullable final Long licenseId,
            @Nullable final String details) {
        return handle.createUpdate("""
                        UPDATE "COMPONENT"
                           SET "LICENSE_ID" = COALESCE(:licenseId, "LICENSE_ID")
                             , "LICENSE_EXPRESSION" = CASE WHEN :licenseId IS NULL
                                                           THEN "LICENSE_EXPRESSION" ELSE NULL END
                             , "TEXT" = COALESCE(:details, "TEXT")
                         WHERE "PROJECT_ID" = :projectId
                           AND COALESCE("PURL", '') = COALESCE(:purl, '')
                           AND COALESCE("GROUP", '') = COALESCE(:group, '')
                           AND "NAME" = :name
                           AND COALESCE("VERSION", '') = COALESCE(:version, '')
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .bind("licenseId", licenseId)
                .bind("details", details)
                .execute();
    }

    /**
     * Stores the BOM-declared license snapshot on an analysis; used to
     * restore the uploaded value when the override is cleared.
     */
    public void updateDeclaredSnapshot(
            final long analysisId,
            @Nullable final Long declaredLicenseId,
            @Nullable final String declaredLicenseName,
            @Nullable final String declaredLicenseExpression) {
        handle.createUpdate("""
                        UPDATE "COMPONENT_ANALYSIS"
                           SET "DECLARED_LICENSE_ID" = :declaredLicenseId
                             , "DECLARED_LICENSE_NAME" = :declaredLicenseName
                             , "DECLARED_LICENSE_EXPRESSION" = :declaredLicenseExpression
                         WHERE "ID" = :analysisId
                        """)
                .bind("analysisId", analysisId)
                .bind("declaredLicenseId", declaredLicenseId)
                .bind("declaredLicenseName", declaredLicenseName)
                .bind("declaredLicenseExpression", declaredLicenseExpression)
                .execute();
    }

    /**
     * Restores the declared-license snapshot onto the project's currently
     * matching component rows — the instant part of clearing an override.
     */
    public int restoreDeclaredLicense(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version,
            @Nullable final Long declaredLicenseId,
            @Nullable final String declaredLicenseName,
            @Nullable final String declaredLicenseExpression) {
        return handle.createUpdate("""
                        UPDATE "COMPONENT"
                           SET "LICENSE_ID" = :declaredLicenseId
                             , "LICENSE" = :declaredLicenseName
                             , "LICENSE_EXPRESSION" = :declaredLicenseExpression
                         WHERE "PROJECT_ID" = :projectId
                           AND COALESCE("PURL", '') = COALESCE(:purl, '')
                           AND COALESCE("GROUP", '') = COALESCE(:group, '')
                           AND "NAME" = :name
                           AND COALESCE("VERSION", '') = COALESCE(:version, '')
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .bind("declaredLicenseId", declaredLicenseId)
                .bind("declaredLicenseName", declaredLicenseName)
                .bind("declaredLicenseExpression", declaredLicenseExpression)
                .execute();
    }

    public record ComponentLicenseRow(
            @Nullable Long licenseId,
            @Nullable String licenseName,
            @Nullable String licenseExpression) {
    }

    /**
     * Current license fields of the first component matching the identity —
     * the values captured as the declared snapshot when an override is set.
     */
    public Optional<ComponentLicenseRow> getComponentLicense(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version) {
        return handle.createQuery("""
                        SELECT "LICENSE_ID", "LICENSE", "LICENSE_EXPRESSION"
                          FROM "COMPONENT"
                         WHERE "PROJECT_ID" = :projectId
                           AND COALESCE("PURL", '') = COALESCE(:purl, '')
                           AND COALESCE("GROUP", '') = COALESCE(:group, '')
                           AND "NAME" = :name
                           AND COALESCE("VERSION", '') = COALESCE(:version, '')
                         LIMIT 1
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .map((rs, ctx) -> new ComponentLicenseRow(
                        rs.getObject("LICENSE_ID", Long.class),
                        rs.getString("LICENSE"),
                        rs.getString("LICENSE_EXPRESSION")))
                .findOne();
    }

    /**
     * Create-or-update by a component policy. Manual analyses
     * (POLICY_ID IS NULL) are never modified — the empty Optional says the
     * policy lost to a manual decision.
     */
    public Optional<Long> upsertPolicyAnalysis(
            final long projectId,
            @Nullable final String purl,
            @Nullable final String group,
            final String name,
            @Nullable final String version,
            @Nullable final Long licenseId,
            @Nullable final String details,
            final long policyId) {
        return handle.createQuery("""
                        INSERT INTO "COMPONENT_ANALYSIS"
                          ("PROJECT_ID", "PURL", "GROUP", "NAME", "VERSION",
                           "LICENSE_ID", "DETAILS", "POLICY_ID")
                        VALUES
                          (:projectId, :purl, :group, :name, :version,
                           :licenseId, :details, :policyId)
                        ON CONFLICT ("PROJECT_ID", COALESCE("PURL", ''), COALESCE("GROUP", ''),
                                     "NAME", COALESCE("VERSION", ''))
                        DO UPDATE
                           SET "LICENSE_ID" = EXCLUDED."LICENSE_ID"
                             , "DETAILS" = EXCLUDED."DETAILS"
                             , "POLICY_ID" = EXCLUDED."POLICY_ID"
                             , "UPDATED_AT" = NOW()
                         WHERE "COMPONENT_ANALYSIS"."POLICY_ID" IS NOT NULL
                        RETURNING "ID"
                        """)
                .bind("projectId", projectId)
                .bind("purl", purl)
                .bind("group", group)
                .bind("name", name)
                .bind("version", version)
                .bind("licenseId", licenseId)
                .bind("details", details)
                .bind("policyId", policyId)
                .mapTo(Long.class)
                .findOne();
    }

    public boolean delete(final long analysisId) {
        return handle.createUpdate("""
                        DELETE FROM "COMPONENT_ANALYSIS" WHERE "ID" = :id
                        """)
                .bind("id", analysisId)
                .execute() > 0;
    }

    public record CreateCommentCommand(long componentAnalysisId, @Nullable String commenter, String comment) {
    }

    public int createComments(final Collection<CreateCommentCommand> commands) {
        final var batch = handle.prepareBatch("""
                INSERT INTO "COMPONENT_ANALYSIS_COMMENT"
                  ("COMPONENT_ANALYSIS_ID", "COMMENTER", "COMMENT")
                VALUES
                  (:componentAnalysisId, :commenter, :comment)
                """);
        for (final CreateCommentCommand command : commands) {
            batch.bind("componentAnalysisId", command.componentAnalysisId())
                    .bind("commenter", command.commenter())
                    .bind("comment", command.comment())
                    .add();
        }
        return batch.execute().length;
    }

    public List<ComponentAnalysisComment> getComments(final long componentAnalysisId) {
        return handle.createQuery("""
                        SELECT "ID", "TIMESTAMP", "COMMENTER", "COMMENT"
                          FROM "COMPONENT_ANALYSIS_COMMENT"
                         WHERE "COMPONENT_ANALYSIS_ID" = :componentAnalysisId
                         ORDER BY "TIMESTAMP", "ID"
                        """)
                .bind("componentAnalysisId", componentAnalysisId)
                .map(COMMENT_ROW_MAPPER)
                .list();
    }
}
