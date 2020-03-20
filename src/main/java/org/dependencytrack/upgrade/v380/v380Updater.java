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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.upgrade.v380;

import alpine.Config;
import alpine.logging.Logger;
import alpine.persistence.AlpineQueryManager;
import alpine.upgrade.AbstractUpgradeItem;
import alpine.util.DbUtil;
import org.apache.commons.io.FileDeleteStrategy;
import org.dependencytrack.model.Repository;
import org.dependencytrack.persistence.QueryManager;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;

public class v380Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = Logger.getLogger(v380Updater.class);
    private static final String STMT_1 = "UPDATE \"REPOSITORY\" SET \"URL\" = 'https://repo1.maven.org/maven2/' WHERE \"TYPE\" = 'MAVEN' AND \"IDENTIFIER\" = 'central'";
    private static final String STMT_2 = "DELETE FROM \"VULNERABLESOFTWARE_VULNERABILITIES\"";
    private static final String STMT_3 = "DELETE FROM \"VULNERABLESOFTWARE\"";
    private static final String STMT_4 = "UPDATE \"REPOSITORY\" SET \"INTERNAL\" = FALSE";
    private static final String STMT_4_ALT = "UPDATE \"REPOSITORY\" SET \"INTERNAL\" = 0";
    private static final String STMT_5 = "SELECT * FROM \"REPOSITORY\"";
    private static final String STMT_6 = "UPDATE \"REPOSITORY\" SET \"UUID\" = ? WHERE \"ID\" = ?";

    @Override
    public String getSchemaVersion() {
        return "3.8.0";
    }

    @Override
    public void executeUpgrade(final AlpineQueryManager alpineQueryManager, final Connection connection) throws Exception {
        LOGGER.info("Updating Maven Central URL");
        DbUtil.executeUpdate(connection, STMT_1);

        LOGGER.info("Purging internal vulnerable software dictionary. This may take several minutes...");
        DbUtil.executeUpdate(connection, STMT_2);
        DbUtil.executeUpdate(connection, STMT_3);

        LOGGER.info("Deleting NIST directory");
        try {
            final String NIST_ROOT_DIR = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "nist";
            FileDeleteStrategy.FORCE.delete(new File(NIST_ROOT_DIR));
        } catch (IOException e) {
            LOGGER.error("An error occurred deleting the NIST directory", e);
        }

        LOGGER.info("Deleting index directory");
        try {
            final String INDEX_ROOT_DIR = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "index";
            FileDeleteStrategy.FORCE.delete(new File(INDEX_ROOT_DIR));
        } catch (IOException e) {
            LOGGER.error("An error occurred deleting the index directory", e);
        }

        LOGGER.info("Updating existing repositories to be non-internal");
        try {
            DbUtil.executeUpdate(connection, STMT_4);
        } catch (Exception e) {
            LOGGER.info("Internal field is likely not boolean. Attempting repository internal status update assuming bit field");
            DbUtil.executeUpdate(connection, STMT_4_ALT);
        }

        LOGGER.info("Assigning UUIDs to existing repositories");
        final Statement stmt = connection.createStatement();
        try {
            final ResultSet rs = stmt.executeQuery(STMT_5);
            while (rs.next()) {
                final PreparedStatement ps = connection.prepareStatement(STMT_6);
                ps.setString(1, UUID.randomUUID().toString());
                ps.setLong(2, rs.getLong(1));
                ps.executeUpdate();
            }
        } finally {
            stmt.close();
        }
    }
}
