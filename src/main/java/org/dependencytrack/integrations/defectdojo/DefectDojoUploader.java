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
package org.dependencytrack.integrations.defectdojo;

import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.FindingPackagingFormat;
import org.dependencytrack.integrations.ProjectFindingUploader;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_API_KEY;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_REIMPORT_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_URL;

public class DefectDojoUploader extends AbstractIntegrationPoint implements ProjectFindingUploader {

    private static final Logger LOGGER = Logger.getLogger(DefectDojoUploader.class);
    private static final String ENGAGEMENTID_PROPERTY = "defectdojo.engagementId";
    private static final String REIMPORT_PROPERTY = "defectdojo.reimport";
    private static final String DO_NOT_REACTIVATE_PROPERTY = "defectdojo.doNotReactivate";


    public boolean isReimportConfigured(final Project project) {
        final ProjectProperty reimport = qm.getProjectProperty(project, DEFECTDOJO_ENABLED.getGroupName(), REIMPORT_PROPERTY);
        if (reimport != null) {
            return Boolean.parseBoolean(reimport.getPropertyValue());
        } else {
            return false;
        }
    }

    public boolean isDoNotReactivateConfigured(final Project project) {
        final ProjectProperty reactivate = qm.getProjectProperty(project, DEFECTDOJO_ENABLED.getGroupName(), DO_NOT_REACTIVATE_PROPERTY);
        if (reactivate != null) {
            return Boolean.parseBoolean(reactivate.getPropertyValue());
        } else {
            return false;
        }
    }

    @Override
    public String name() {
        return "DefectDojo";
    }

    @Override
    public String description() {
        return "Pushes Dependency-Track findings to DefectDojo";
    }

    @Override
    public boolean isEnabled() {
        final ConfigProperty enabled = qm.getConfigProperty(DEFECTDOJO_ENABLED.getGroupName(), DEFECTDOJO_ENABLED.getPropertyName());
        return enabled != null && Boolean.valueOf(enabled.getPropertyValue());
    }

    @Override
    public boolean isProjectConfigured(final Project project) {
        final ProjectProperty engagementId = qm.getProjectProperty(project, DEFECTDOJO_ENABLED.getGroupName(), ENGAGEMENTID_PROPERTY);
        return engagementId != null && engagementId.getPropertyValue() != null;
    }

    @Override
    public InputStream process(final Project project, final List<Finding> findings) {
        final JSONObject fpf = new FindingPackagingFormat(project.getUuid(), findings).getDocument();
        return new ByteArrayInputStream(fpf.toString(2).getBytes());
    }

    @Override
    public void upload(final Project project, final InputStream payload) {
        final ConfigProperty defectDojoUrl = qm.getConfigProperty(DEFECTDOJO_URL.getGroupName(), DEFECTDOJO_URL.getPropertyName());
        final ConfigProperty apiKey = qm.getConfigProperty(DEFECTDOJO_API_KEY.getGroupName(), DEFECTDOJO_API_KEY.getPropertyName());
        final ConfigProperty globalReimportEnabled = qm.getConfigProperty(DEFECTDOJO_REIMPORT_ENABLED.getGroupName(), DEFECTDOJO_REIMPORT_ENABLED.getPropertyName());
        final ProjectProperty engagementId = qm.getProjectProperty(project, DEFECTDOJO_ENABLED.getGroupName(), ENGAGEMENTID_PROPERTY);
        try {
            final DefectDojoClient client = new DefectDojoClient(this, new URL(defectDojoUrl.getPropertyValue()));
            final ArrayList testsIds = client.getDojoTestIds(apiKey.getPropertyValue(), engagementId.getPropertyValue());
            final String testId = client.getDojoTestId(engagementId.getPropertyValue(), testsIds);
            if (isReimportConfigured(project) || Boolean.parseBoolean(globalReimportEnabled.getPropertyValue())) {
                LOGGER.debug("Found existing test Id: " + testId);
                if (testId.equals("")) {
                    client.uploadDependencyTrackFindings(apiKey.getPropertyValue(), engagementId.getPropertyValue(), payload);
                } else {
                    client.reimportDependencyTrackFindings(apiKey.getPropertyValue(), engagementId.getPropertyValue(), payload, testId, isDoNotReactivateConfigured(project));
                }
            } else {
                client.uploadDependencyTrackFindings(apiKey.getPropertyValue(), engagementId.getPropertyValue(), payload);
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred attempting to upload findings to DefectDojo", e);
            handleException(LOGGER, e);
        }
    }
}
