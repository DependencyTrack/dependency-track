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
        createDependencyMetricsIndex(connection);
        createComponentCompositeProjectIdIndex(connection);
        createComponentVulnerabilitiesCompositeIndex(connection);
        createProjectMetricsLastOccurrenceIndex(connection);
        createVulnerabilityCompositeSourceVulnIdIndex(connection);
        createFindingAttributionCompositeIndex(connection);
        createAnalysisCompositeIndices(connection);
        createProjectActiveIndex(connection);
        analyzeNewIndexes(connection);
    }

    private void createDependencyMetricsIndex(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'DEPENDENCYMETRICS' for (COMPONENT_ID, LAST_OCCURRENCE DESC)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "DEPENDENCYMETRICS_COMPOSITE_LAST_OCCURRENCE_IDX"
                      ON public."DEPENDENCYMETRICS"("COMPONENT_ID", "LAST_OCCURRENCE" DESC)
                    """);
        }
    }

    private void createComponentCompositeProjectIdIndex(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'COMPONENT' for (PROJECT_ID, ID DESC)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "COMPONENT_COMPOSITE_PROJECT_ID_IDX"
                      ON public."COMPONENT"("PROJECT_ID", "ID" DESC)
                    """);
        }
    }

    private void createComponentVulnerabilitiesCompositeIndex(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating partial index on 'COMPONENTS_VULNERABILITIES' for (VULNERABILITY_ID, COMPONENT_ID)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS components_vulnerabilities_composite_component_idx
                      ON public."COMPONENTS_VULNERABILITIES"("VULNERABILITY_ID", "COMPONENT_ID");
                    """);
        }
    }

    private void createProjectMetricsLastOccurrenceIndex(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'PROJECTMETRICS' for (PROJECT_ID, LAST_OCCURRENCE DESC)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "PROJECTMETRICS_COMPOSITE_LAST_OCCURRENCE_IDX"
                      ON public."PROJECTMETRICS"("PROJECT_ID", "LAST_OCCURRENCE" DESC)
                    """);
        }
    }

    private void createVulnerabilityCompositeSourceVulnIdIndex(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'VULNERABILITY' for (SOURCE, VULNID)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "VULNERABILITY_COMPOSITE_SOURCE_VULNID_IDX"
                      ON public."VULNERABILITY"("SOURCE", "VULNID")
                    """);
        }
    }

    private void createFindingAttributionCompositeIndex(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'FINDINGATTRIBUTION' for (COMPONENT_ID, VULNERABILITY_ID, ATTRIBUTED_ON DESC)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "FINDINGATTRIBUTION_COMPOSITE_VULNERABILITY_ATTRIBUTED_IDX"
                      ON public."FINDINGATTRIBUTION"(
                        "COMPONENT_ID",
                        "VULNERABILITY_ID",
                        "ATTRIBUTED_ON" DESC
                      )
                    """);
        }
    }

    private void createAnalysisCompositeIndices(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating composite index on 'ANALYSIS' for (COMPONENT_ID, VULNERABILITY_ID, PROJECT_ID)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "ANALYSIS_COMPOSITE_VULNERABILITY_PROJECT_IDX"
                      ON public."ANALYSIS"(
                        "COMPONENT_ID",
                        "VULNERABILITY_ID",
                        "PROJECT_ID"
                      )
                    """);

            LOGGER.info("Creating composite index on 'ANALYSIS' for (COMPONENT_ID, VULNERABILITY_ID, PROJECT_ID, SUPPRESSED)");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "ANALYSIS_COMPOSITE_VULNERABILITY_PROJECT_SUPPRESSED_IDX"
                      ON public."ANALYSIS"(
                        "COMPONENT_ID",
                        "VULNERABILITY_ID",
                        "PROJECT_ID",
                        "SUPPRESSED"
                      )
                    """);
        }
    }

    private void createProjectActiveIndex(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Creating partial index on 'PROJECT' for ACTIVE = true");
            stmt.execute(/* language=SQL */ """
                    CREATE INDEX IF NOT EXISTS "PROJECT_ACTIVE_IDX"
                      ON public."PROJECT"("ID")
                     WHERE "ACTIVE" = true
                    """);
        }
    }

    private void analyzeNewIndexes(final Connection connection) throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            LOGGER.info("Running ANALYZE on tables with new indexes");
            stmt.execute(/* language=SQL */ """
                    ANALYZE
                      "DEPENDENCYMETRICS",
                      "COMPONENT",
                      "COMPONENTS_VULNERABILITIES",
                      "PROJECTMETRICS",
                      "VULNERABILITY",
                      "FINDINGATTRIBUTION",
                      "ANALYSIS",
                      "PROJECT"
                    """);
        }
    }
}
