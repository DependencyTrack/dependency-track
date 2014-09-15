/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) Axway. All Rights Reserved.
 */

package org.owasp.dependencytrack.tasks;

import org.owasp.dependencycheck.data.update.CachedWebDataSource;
import org.owasp.dependencycheck.data.update.UpdateService;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencytrack.Constants;
import org.owasp.dependencytrack.util.ZipUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

import java.io.IOException;
import java.util.Iterator;

public class DependencyCheckDataUpdater {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DependencyCheckDataUpdater.class);


    /**
     * Updates the Dependency-Check data directory.
     */
    @Scheduled(fixedRate = 86400000) // every 24 hours
    public void doUpdates() {
        // Configure the data directory
        Settings.setString(Settings.KEYS.DATA_DIRECTORY, Constants.DATA_DIR);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Performing scheduled update of Dependency-Check data directory");
        }

        //Cycles through the cached web data sources and calls update on all of them.
        final UpdateService service = new UpdateService(this.getClass().getClassLoader());
        final Iterator<CachedWebDataSource> iterator = service.getDataSources();
        while (iterator.hasNext()) {
            final CachedWebDataSource source = iterator.next();
            try {
                source.update();
                packageDataDirectory();
            } catch (UpdateException ex) {
                if (LOGGER.isWarnEnabled()) {
                    LOGGER.warn("Unable to update Cached Web DataSource");
                }
            }
        }
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Update complete");
        }
    }

    /**
     * Packages the Dependency-Check data directory into a ZIP archive.
     */
    private void packageDataDirectory() {
        try {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Packaging Dependency-Check data directory");
            }
            ZipUtil.createZip(Constants.DATA_DIR, Constants.DATA_ZIP);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Dependency-Check data directory packaging complete");
            }
        } catch (IOException e) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("An error occurred packaging the data directory: " + e.getMessage());
            }
        }
    }

}
