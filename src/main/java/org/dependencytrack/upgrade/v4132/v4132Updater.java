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
package org.dependencytrack.upgrade.v4132;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class v4132Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4132Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.13.2";
    }



    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        createAnalysisCompositeIndices(connection);
        createComponentCompositeIndices(connection);
        createDependencyMetricsIndices(connection);
        createFindingAttributionCompositeIndices(connection);
        createProjectCompositeIndices(connection);
        createProjectMetricsCompositeIndices(connection);
        createVulnerabilityCompositeIndices(connection);
        analyzeNewIndexes(connection);
    }

    private void createAnalysisCompositeIndices(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'ANALYSIS' for (COMPONENT_ID, VULNERABILITY_ID, PROJECT_ID)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "ANALYSIS_COMPOSITE_VULNERABILITY_PROJECT_IDX"
                      ON "ANALYSIS"(
                        "COMPONENT_ID",
                        "VULNERABILITY_ID",
                        "PROJECT_ID"
                      )
                    """);

            LOGGER.info("Creating composite index on 'ANALYSIS' for (COMPONENT_ID, VULNERABILITY_ID, PROJECT_ID, SUPPRESSED)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "ANALYSIS_COMPOSITE_VULNERABILITY_PROJECT_SUPPRESSED_IDX"
                      ON "ANALYSIS"(
                        "COMPONENT_ID",
                        "VULNERABILITY_ID",
                        "PROJECT_ID",
                        "SUPPRESSED"
                      )
                    """);
        }
    }

    private void createComponentCompositeIndices(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'COMPONENT' for (PROJECT_ID, ID DESC)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "COMPONENT_COMPOSITE_PROJECT_ID_IDX"
                      ON "COMPONENT"("PROJECT_ID", "ID" DESC)
                    """);
        }

        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating partial index on 'COMPONENTS_VULNERABILITIES' for (VULNERABILITY_ID, COMPONENT_ID)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS COMPONENTS_VULNERABILITIES_COMPOSITE_IDX
                      ON "COMPONENTS_VULNERABILITIES"("VULNERABILITY_ID", "COMPONENT_ID");
                    """);
        }
    }
    private void createDependencyMetricsIndices(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'DEPENDENCYMETRICS' for (COMPONENT_ID, LAST_OCCURRENCE DESC)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "DEPENDENCYMETRICS_COMPOSITE_LAST_OCCURRENCE_IDX"
                      ON "DEPENDENCYMETRICS"("COMPONENT_ID", "LAST_OCCURRENCE" DESC)
                    """);
        }
    }

    private void createFindingAttributionCompositeIndices(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'FINDINGATTRIBUTION' for (COMPONENT_ID, VULNERABILITY_ID, ATTRIBUTED_ON DESC)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "FINDINGATTRIBUTION_COMPOSITE_VULNERABILITY_ATTRIBUTED_IDX"
                      ON "FINDINGATTRIBUTION"(
                        "COMPONENT_ID",
                        "VULNERABILITY_ID",
                        "ATTRIBUTED_ON" DESC
                      )
                    """);
        }
    }

    private void createProjectCompositeIndices(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating index on 'PROJECT' for (ID, ACTIVE) (For use with Active = true)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "PROJECT_ACTIVE_IDX"
                      ON "PROJECT"("ACTIVE", "ID")
                    """);
        }
    }

    private void createProjectMetricsCompositeIndices(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'PROJECTMETRICS' for (PROJECT_ID, LAST_OCCURRENCE DESC)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "PROJECTMETRICS_COMPOSITE_LAST_OCCURRENCE_IDX"
                      ON "PROJECTMETRICS"("PROJECT_ID", "LAST_OCCURRENCE" DESC)
                    """);
        }
    }

    private void createVulnerabilityCompositeIndices(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'VULNERABILITY' for (SOURCE, VULNID)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "VULNERABILITY_COMPOSITE_SOURCE_VULNID_IDX"
                      ON "VULNERABILITY"("SOURCE", "VULNID")
                    """);
        }
    }

    private void analyzeNewIndexes(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Running ANALYZE on tables with new indexes");
            stmt.execute(/* language=SQL */ """
                    ANALYZE
                      "ANALYSIS",
                      "COMPONENT",
                      "COMPONENTS_VULNERABILITIES",
                      "DEPENDENCYMETRICS",
                      "FINDINGATTRIBUTION",
                      "PROJECT"
                      "PROJECTMETRICS",
                      "VULNERABILITY",
                    """);
        }
    }
}
