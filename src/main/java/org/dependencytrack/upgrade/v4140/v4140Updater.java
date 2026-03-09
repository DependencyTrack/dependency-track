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
package org.dependencytrack.upgrade.v4140;

import alpine.persistence.AlpineQueryManager;
import alpine.server.upgrade.AbstractUpgradeItem;
import org.dependencytrack.tasks.NistMirrorTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class v4140Updater extends AbstractUpgradeItem {

    private static final Logger LOGGER = LoggerFactory.getLogger(v4140Updater.class);

    @Override
    public String getSchemaVersion() {
        return "4.14.0";
    }

    @Override
    public void executeUpgrade(AlpineQueryManager qm, Connection connection) throws Exception {
        resetVulnSourceWatermarks(connection);
        deleteNvdFeedTimestampFiles();
    }

    private void deleteNvdFeedTimestampFiles() {
        final Path nvdMirrorDir = NistMirrorTask.DEFAULT_NVD_MIRROR_DIR;
        if (!Files.isDirectory(nvdMirrorDir)) {
            return;
        }

        LOGGER.info("Deleting NVD feed timestamp files to force re-download");
        try (final DirectoryStream<Path> stream = Files.newDirectoryStream(nvdMirrorDir, "*.json.gz.ts")) {
            for (final Path tsFile : stream) {
                LOGGER.info("Deleting {}", tsFile.getFileName());
                Files.delete(tsFile);
            }
        } catch (IOException e) {
            LOGGER.warn("""
                    Failed to delete NVD feed timestamp files. \
                    You may need to delete them manually and restart Dependency-Track \
                    to force a re-download.""", e);
        }
    }

    private void resetVulnSourceWatermarks(Connection connection) throws SQLException {
        LOGGER.info("""
                Resetting watermarks for incremental vulnerability source mirroring. \
                Sources will perform a full mirror for their next scheduled invocation. \
                This is necessary to support the backfill of CVSSv4 data.""");

        try (final Statement statement = connection.createStatement()) {
            statement.execute(/* language=SQL */ """
                    UPDATE "CONFIGPROPERTY"
                       SET "PROPERTYVALUE" = NULL
                     WHERE "GROUPNAME" = 'vuln-source'
                       AND "PROPERTYNAME" = 'github.advisories.last.modified.epoch.seconds'
                    """);
            statement.execute(/* language=SQL */ """
                    UPDATE "CONFIGPROPERTY"
                       SET "PROPERTYVALUE" = NULL
                     WHERE "GROUPNAME" = 'vuln-source'
                       AND "PROPERTYNAME" = 'nvd.api.last.modified.epoch.seconds'
                    """);
        }
    }

}
