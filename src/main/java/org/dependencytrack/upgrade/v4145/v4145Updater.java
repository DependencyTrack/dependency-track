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
package org.dependencytrack.upgrade.v4145;

import alpine.common.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;
import java.util.regex.Pattern;

public class v4145Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4145Updater.class);
    private static final Pattern PYPI_NAME_SEPARATORS = Pattern.compile("[-_.]+");

    @Override
    public String getSchemaVersion() {
        return "4.14.5";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        normalizePypiPurlNames(connection);
        normalizeNugetPurlNames(connection);
    }

    private void normalizePypiPurlNames(final Connection connection) throws SQLException {
        LOGGER.info("Normalizing \"VULNERABLESOFTWARE\" PyPI package names");
        try (final Statement selectStatement = connection.createStatement();
             final PreparedStatement updateStatement = connection.prepareStatement(/* language=SQL */ """
                     UPDATE "VULNERABLESOFTWARE" SET "PURL_NAME" = ? WHERE "ID" = ?
                     """)) {
            final ResultSet rs = selectStatement.executeQuery(/* language=SQL */ """
                    SELECT "ID", "PURL_NAME"
                      FROM "VULNERABLESOFTWARE"
                     WHERE "PURL_TYPE" = 'pypi'
                       AND "PURL_NAMESPACE" IS NULL
                       AND ("PURL_NAME" LIKE '%.%'
                            OR "PURL_NAME" LIKE '%!_%' ESCAPE '!'
                            OR "PURL_NAME" LIKE '%--%')
                    """);
            while (rs.next()) {
                updateStatement.setString(1, PYPI_NAME_SEPARATORS.matcher(rs.getString(2)).replaceAll("-"));
                updateStatement.setLong(2, rs.getLong(1));
                updateStatement.addBatch();
            }
            updateStatement.executeBatch();
        }
    }

    private void normalizeNugetPurlNames(final Connection connection) throws SQLException {
        LOGGER.info("Normalizing \"VULNERABLESOFTWARE\" NuGet package names");
        try (final Statement selectStatement = connection.createStatement();
             final PreparedStatement updateStatement = connection.prepareStatement(/* language=SQL */ """
                     UPDATE "VULNERABLESOFTWARE" SET "PURL_NAME" = ? WHERE "ID" = ?
                     """)) {
            final ResultSet rs = selectStatement.executeQuery(/* language=SQL */ """
                    SELECT "ID", "PURL_NAME"
                      FROM "VULNERABLESOFTWARE"
                     WHERE "PURL_TYPE" = 'nuget'
                       AND "PURL_NAMESPACE" IS NULL
                    """);
            while (rs.next()) {
                // Compared in Java: "PURL_NAME" <> LOWER("PURL_NAME") excludes every row under case-insensitive collations.
                final String purlName = rs.getString(2);
                final String normalizedPurlName = purlName.toLowerCase(Locale.ROOT);
                if (!normalizedPurlName.equals(purlName)) {
                    updateStatement.setString(1, normalizedPurlName);
                    updateStatement.setLong(2, rs.getLong(1));
                    updateStatement.addBatch();
                }
            }
            updateStatement.executeBatch();
        }
    }

}
