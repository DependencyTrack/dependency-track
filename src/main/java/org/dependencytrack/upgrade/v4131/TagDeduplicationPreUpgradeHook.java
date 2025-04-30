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
package org.dependencytrack.upgrade.v4131;

import alpine.common.logging.Logger;
import alpine.common.util.VersionComparator;
import alpine.server.upgrade.UpgradeMetaProcessor;
import org.dependencytrack.upgrade.PreUpgradeHook;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * A {@link PreUpgradeHook} to deduplicate tags and their relationships.
 * <p>
 * The v4.13.1 schema defines a unique constraint on {@code "TAG"."NAME"},
 * and primary keys on tag relationship join tables. For the creation of those
 * constraints to succeed, duplicates must already be cleaned up.
 */
public class TagDeduplicationPreUpgradeHook implements PreUpgradeHook {

    private static final Logger LOGGER = Logger.getLogger(TagDeduplicationPreUpgradeHook.class);

    @Override
    public int order() {
        return 2;
    }

    @Override
    public boolean shouldExecute(final UpgradeMetaProcessor upgradeProcessor) {
        final VersionComparator currentSchemaVersion = upgradeProcessor.getSchemaVersion();
        return currentSchemaVersion != null && currentSchemaVersion.isOlderThan(new VersionComparator("4.13.1"));
    }

    @Override
    public void execute(final Connection connection) throws Exception {
        final boolean hasNotificationRuleTagsTable;
        try (final ResultSet rs = connection.getMetaData().getTables(null, null, "NOTIFICATIONRULE_TAGS", null)) {
            hasNotificationRuleTagsTable = rs.next();
        }
        if (!hasNotificationRuleTagsTable) {
            // Happens when directly upgrading from a version older than v4.11.0.
            LOGGER.info("NOTIFICATIONRULE_TAGS table does not exist yet");
        }

        final Set<TagDuplicateRecord> dupeTagRecords = getDuplicateTags(connection);
        if (!dupeTagRecords.isEmpty()) {
            LOGGER.info("Identified %s duplicate tag records; Updating relationships".formatted(dupeTagRecords.size()));
            if (hasNotificationRuleTagsTable) {
                updateTagRelationships(connection, dupeTagRecords, "NOTIFICATIONRULE_TAGS");
            }
            updateTagRelationships(connection, dupeTagRecords, "POLICY_TAGS");
            updateTagRelationships(connection, dupeTagRecords, "PROJECTS_TAGS");
            updateCollectionTags(connection, dupeTagRecords);

            LOGGER.info("Deleting duplicate records of %s tags".formatted(dupeTagRecords.size()));
            deleteDuplicateTags(connection, dupeTagRecords);
        } else {
            LOGGER.info("No duplicate tags found");
        }

        if (hasNotificationRuleTagsTable) {
            final Set<TagRelationshipRecord> dupeNotificationRuleTagsRecords =
                    getDuplicateTagsRelationshipRecords(connection, "NOTIFICATIONRULE_TAGS", "NOTIFICATIONRULE_ID");
            if (!dupeNotificationRuleTagsRecords.isEmpty()) {
                LOGGER.info("De-duplicating %d records in \"NOTIFICATIONRULE_TAGS\" table".formatted(dupeNotificationRuleTagsRecords.size()));
                deduplicateTagRelationshipRecords(connection, dupeNotificationRuleTagsRecords, "NOTIFICATIONRULE_TAGS", "NOTIFICATIONRULE_ID");
            } else {
                LOGGER.info("No duplicate \"NOTIFICATIONRULE_TAGS\" records found");
            }
        }

        final Set<TagRelationshipRecord> dupePolicyTagsRecords =
                getDuplicateTagsRelationshipRecords(connection, "POLICY_TAGS", "POLICY_ID");
        if (!dupePolicyTagsRecords.isEmpty()) {
            LOGGER.info("De-duplicating %d records in \"POLICY_TAGS\" table".formatted(dupePolicyTagsRecords.size()));
            deduplicateTagRelationshipRecords(connection, dupePolicyTagsRecords, "POLICY_TAGS", "POLICY_ID");
        } else {
            LOGGER.info("No duplicate \"POLICY_TAGS\" records found");
        }

        final Set<TagRelationshipRecord> dupeProjectsTagsRecords =
                getDuplicateTagsRelationshipRecords(connection, "PROJECTS_TAGS", "PROJECT_ID");
        if (!dupeProjectsTagsRecords.isEmpty()) {
            LOGGER.info("De-duplicating %d records in \"PROJECTS_TAGS\" table".formatted(dupeProjectsTagsRecords.size()));
            deduplicateTagRelationshipRecords(connection, dupeProjectsTagsRecords, "PROJECTS_TAGS", "PROJECT_ID");
        } else {
            LOGGER.info("No duplicate \"PROJECTS_TAGS\" records found");
        }
    }

    private record TagDuplicateRecord(String name, long canonicalId) {
    }

    private Set<TagDuplicateRecord> getDuplicateTags(final Connection connection) throws SQLException {
        final var duplicateTagNames = new HashSet<TagDuplicateRecord>();

        try (final PreparedStatement ps = connection.prepareStatement("""
                SELECT "NAME"
                     , MIN("ID")
                  FROM "TAG"
                 GROUP BY "NAME"
                HAVING COUNT(*) > 1
                """)) {
            final ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                duplicateTagNames.add(new TagDuplicateRecord(rs.getString(1), rs.getLong(2)));
            }
        }

        return duplicateTagNames;
    }

    private void updateTagRelationships(
            final Connection connection,
            final Collection<TagDuplicateRecord> duplicateTagRecords,
            final String tableName) throws SQLException {
        try (final PreparedStatement ps = connection.prepareStatement(/* language=SQL */ """
                UPDATE "%s"
                   SET "TAG_ID" = ?
                 WHERE "TAG_ID" IN (SELECT "ID" FROM "TAG" WHERE "NAME" = ? AND "ID" != ?)
                """.formatted(tableName))) {
            for (final TagDuplicateRecord duplicateTagRecord : duplicateTagRecords) {
                ps.setLong(1, duplicateTagRecord.canonicalId());
                ps.setString(2, duplicateTagRecord.name());
                ps.setLong(3, duplicateTagRecord.canonicalId());
                int rowsUpdated = ps.executeUpdate();
                if (rowsUpdated > 0) {
                    LOGGER.info("Updated %d %s records for tag %s".formatted(
                            rowsUpdated, tableName, duplicateTagRecord.name()));
                }
            }
        }
    }

    private void updateCollectionTags(
            final Connection connection,
            final Collection<TagDuplicateRecord> duplicateTagRecords) throws SQLException {
        // NB: When upgrading from < v4.13.0, the COLLECTION_TAG column does not yet exist.
        // Executing the UPDATE query would cause the hook to fail entirely.
        try (final ResultSet rs = connection.getMetaData().getColumns(null, null, "PROJECT", "COLLECTION_TAG")) {
            if (!rs.next()) {
                LOGGER.info("\"PROJECT\".\"COLLECTION_TAG\" column doesn't exist yet; No PROJECT records to update");
                return;
            }
        }

        try (final PreparedStatement ps = connection.prepareStatement("""
                UPDATE "PROJECT"
                   SET "COLLECTION_TAG" = ?
                 WHERE "COLLECTION_TAG" IN (SELECT "ID" FROM "TAG" WHERE "NAME" = ? AND "ID" != ?)
                """)) {
            for (final TagDuplicateRecord duplicateTagRecord : duplicateTagRecords) {
                ps.setLong(1, duplicateTagRecord.canonicalId());
                ps.setString(2, duplicateTagRecord.name());
                ps.setLong(3, duplicateTagRecord.canonicalId());
                int recordsUpdated = ps.executeUpdate();
                if (recordsUpdated > 0) {
                    LOGGER.info("Updated \"COLLECTION_TAG\" columns of %d \"PROJECT\" records for tag %s".formatted(
                            recordsUpdated, duplicateTagRecord.name()));
                }
            }
        }
    }

    private void deleteDuplicateTags(
            final Connection connection,
            final Collection<TagDuplicateRecord> duplicateTagRecords) throws SQLException {
        try (final PreparedStatement ps = connection.prepareStatement("""
                DELETE FROM "TAG"
                 WHERE "NAME" = ?
                   AND "ID" != ?
                """)) {
            for (final TagDuplicateRecord dupeRecord : duplicateTagRecords) {
                ps.setString(1, dupeRecord.name());
                ps.setLong(2, dupeRecord.canonicalId());
                final int rowsDeleted = ps.executeUpdate();
                if (rowsDeleted > 0) {
                    LOGGER.info("Deleted %d duplicate records for tag %s".formatted(rowsDeleted, dupeRecord.name()));
                }
            }
        }
    }

    private record TagRelationshipRecord(long tagId, long relationshipId) {
    }

    private Set<TagRelationshipRecord> getDuplicateTagsRelationshipRecords(
            final Connection connection,
            final String tableName,
            final String columnName) throws SQLException {
        final var dupeRecords = new HashSet<TagRelationshipRecord>();

        try (final PreparedStatement ps = connection.prepareStatement(/* language=SQL */ """
                SELECT "TAG_ID"
                     , "%s"
                  FROM "%s"
                 GROUP BY "TAG_ID"
                        , "%s"
                HAVING COUNT(*) > 1
                """.formatted(columnName, tableName, columnName))) {
            final ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                dupeRecords.add(new TagRelationshipRecord(rs.getLong(1), rs.getLong(2)));
            }
        }

        return dupeRecords;
    }

    private void deduplicateTagRelationshipRecords(
            final Connection connection,
            final Collection<TagRelationshipRecord> duplicateRecords,
            final String tableName,
            final String columnName) throws SQLException {
        try (final PreparedStatement deleteStmt = connection.prepareStatement(/* language=SQL */ """
                DELETE FROM "%s"
                 WHERE "TAG_ID" = ?
                   AND "%s" = ?
                """.formatted(tableName, columnName));
             final PreparedStatement insertStmt = connection.prepareStatement(/* language=SQL */ """
                     INSERT INTO "%s" ("TAG_ID", "%s")
                     VALUES (?, ?)
                     """.formatted(tableName, columnName))) {
            for (final TagRelationshipRecord dupeRecord : duplicateRecords) {
                deleteStmt.setLong(1, dupeRecord.tagId());
                deleteStmt.setLong(2, dupeRecord.relationshipId());
                deleteStmt.executeUpdate();

                insertStmt.setLong(1, dupeRecord.tagId());
                insertStmt.setLong(2, dupeRecord.relationshipId());
                insertStmt.executeUpdate();
            }
        }
    }

}
