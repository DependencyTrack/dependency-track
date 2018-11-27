/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.integrations.kenna;

import alpine.crypto.DataEncryption;
import alpine.logging.Logger;
import alpine.model.ConfigProperty;
import org.dependencytrack.integrations.FindingsUploader;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.persistence.QueryManager;
import java.io.InputStream;
import java.util.UUID;

import static org.dependencytrack.model.ConfigPropertyConstants.*;

public class KennaSecurityUploader implements FindingsUploader {

    private static final Logger LOGGER = Logger.getLogger(KennaSecurityUploader.class);
    private static final String ASSET_ID_PROPERTY = "kenna.asset.id";
    private static final String API_ROOT = "https://api.kennasecurity.com";

    public boolean isEnabled() {
        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(KENNA_ENABLED.getGroupName(), KENNA_ENABLED.getPropertyName());
            if (enabled != null && !Boolean.valueOf(enabled.getPropertyValue())) {
                return true;
            }
        }
        return false;
    }

    public boolean isProjectConfigured(UUID projectUuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            final ProjectProperty applicationId = qm.getProjectProperty(project, KENNA_ENABLED.getGroupName(), ASSET_ID_PROPERTY);
            if (applicationId != null && applicationId.getPropertyValue() != null) {
                return true;
            }
        }
        return false;
    }

    public void upload(UUID projectUuid, InputStream findingsJson) {
        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty tokenProperty = qm.getConfigProperty(KENNA_TOKEN.getGroupName(), KENNA_TOKEN.getPropertyName());
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            final ProjectProperty assetId = qm.getProjectProperty(project, KENNA_ENABLED.getGroupName(), ASSET_ID_PROPERTY);
            try {
                final String token = DataEncryption.decryptAsString(tokenProperty.getPropertyValue());
                // TODO API Client and data field mappings
            } catch (Exception e) {
                LOGGER.error("An error occurred attempting to upload findings to Kenna Security", e);
            }
        }
    }
}
