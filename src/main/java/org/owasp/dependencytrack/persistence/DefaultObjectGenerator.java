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
 */
package org.owasp.dependencytrack.persistence;

import org.owasp.dependencytrack.logging.Logger;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.parser.spdx.json.SpdxLicenseDetailParser;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

public class DefaultObjectGenerator {

    private static final Logger logger = Logger.getLogger(DefaultObjectGenerator.class);

    DefaultObjectGenerator() {}

    public void initialize() {
        loadDefaultLicenses();
    }

    /**
     * Loads the default licenses into the database if no license data exists.
     */
    private void loadDefaultLicenses() {
        try (QueryManager qm = new QueryManager()) {
            if (qm.getLicenses().size() > 0) {
                return;
            }

            logger.info("Adding default SPDX license definitions to datastore.");

            SpdxLicenseDetailParser parser = new SpdxLicenseDetailParser();
            try {
                List<License> licenses = parser.getLicenseDefinitions();
                for (License license : licenses) {
                    logger.info("Added: " + license.getName());
                    qm.createLicense(license);
                }
            } catch (IOException | URISyntaxException e) {
                logger.error("An error occurred during the parsing SPDX license definitions.");
                logger.error(e.getMessage());
            }
        }
    }

}
