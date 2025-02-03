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
package org.dependencytrack.upgrade.v4130;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HexFormat;

import alpine.common.logging.Logger;
import alpine.model.ApiKey;
import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import alpine.server.util.DbUtil;

public class v4130Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v4130Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.13.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager qm, final Connection connection) throws Exception {
        migrateToHashedApiKey(connection);
    }

    private void migrateToHashedApiKey(final Connection connection) throws Exception {
        LOGGER.error("Store API keys in hashed format!");

        final var ps = connection.prepareStatement("""
        UPDATE "APIKEY"
        SET "APIKEY" = ?, "PUBLIC_ID" = ?, "IS_LEGACY" = ?
        WHERE "ID" = ?
        """);

        if (DbUtil.isMysql() || DbUtil.isMssql()) {
            ps.setInt(3, 1);
        } else {
            ps.setBoolean(3, true);
        }

        try (final Statement statement = connection.createStatement()) {
            statement.execute("""
                SELECT "ID", "APIKEY"
                FROM "APIKEY"
            """);
            try (final ResultSet rs = statement.getResultSet()) {
                String clearKey;
                int id;
                String hashedKey;
                String publicId;
                while (rs.next()) {
                    clearKey = rs.getString("apikey");
                    if (clearKey.length() != ApiKey.LEGACY_FULL_KEY_LENGTH) {
                        continue;
                    }
                    final MessageDigest digest = MessageDigest.getInstance("SHA3-256");
                    id = rs.getInt("id");
                    hashedKey = HexFormat.of().formatHex(digest.digest(ApiKey.getOnlyKeyAsBytes(clearKey, true)));
                    publicId = ApiKey.getPublicId(clearKey, true);

                    ps.setString(1, hashedKey);
                    ps.setString(2, publicId);
                    ps.setInt(4, id);

                    ps.executeUpdate();
                }
            }
        }
    }
}
