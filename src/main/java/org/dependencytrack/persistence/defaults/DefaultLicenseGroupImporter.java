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
package org.dependencytrack.persistence.defaults;

import alpine.logging.Logger;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.persistence.QueryManager;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Imports default LicenseGroup objects into the datastore.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public class DefaultLicenseGroupImporter implements IDefaultObjectImporter {

    private static final Logger LOGGER = Logger.getLogger(DefaultLicenseGroupImporter.class);

    private QueryManager qm;

    public DefaultLicenseGroupImporter(final QueryManager qm) {
        this.qm = qm;
    }

    public boolean shouldImport() {
        if (qm.getLicenseGroups().getTotal() > 0) {
            return false;
        }
        return true;
    }

    public void loadDefaults() throws IOException {
        final File defaultsFile = new File(URLDecoder.decode(getClass().getProtectionDomain().getCodeSource().getLocation().getPath(), UTF_8.name()) + "default-objects/licenseGroups.json");
        final JSONArray licenseGroups = readFile(defaultsFile);
        for (int i = 0; i < licenseGroups.length(); i++) {
            final JSONObject json = licenseGroups.getJSONObject(i);
            final LicenseGroup licenseGroup = new LicenseGroup();
            licenseGroup.setName(json.getString("name"));
            licenseGroup.setRiskWeight(json.getInt("riskWeight"));
            LOGGER.debug("Adding " + licenseGroup.getName());
            final List<License> licenses = new ArrayList<>();
            for (int k=0; k<json.getJSONArray("licenses").length(); k++) {
                final String licenseId = json.getJSONArray("licenses").getString(k);
                final License license = qm.getLicense(licenseId);
                if (license != null) {
                    LOGGER.debug("Adding " + license.getLicenseId() + " to " + licenseGroup.getName());
                    licenses.add(license);
                } else {
                    LOGGER.debug(licenseId + " was not found in the datastore. Unable to add license to " + licenseGroup.getName());
                }
            }
            licenseGroup.setLicenses(licenses);
            qm.persist(licenseGroup);
        }
    }

    private JSONArray readFile(final File file) throws IOException {
        final BufferedReader streamReader = new BufferedReader(new InputStreamReader(new FileInputStream(file), UTF_8));
        final StringBuilder responseStrBuilder = new StringBuilder();
        String inputStr;
        while ((inputStr = streamReader.readLine()) != null)
            responseStrBuilder.append(inputStr);
        return new JSONArray(responseStrBuilder.toString());
    }
}
