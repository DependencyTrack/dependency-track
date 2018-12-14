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
package org.dependencytrack.integrations.fortifyssc;

import alpine.crypto.DataEncryption;
import alpine.logging.Logger;
import alpine.model.ConfigProperty;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.FindingPackagingFormat;
import org.dependencytrack.integrations.FindingUploader;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.persistence.QueryManager;
import org.json.JSONObject;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.List;

import static org.dependencytrack.model.ConfigPropertyConstants.*;

public class FortifySscUploader extends AbstractIntegrationPoint implements FindingUploader {

    private static final Logger LOGGER = Logger.getLogger(FortifySscUploader.class);
    private static final String APPID_PROPERTY = "fortify.ssc.applicationId";

    private QueryManager qm;

    @Override
    public void setQueryManager(QueryManager qm) {
        this.qm = qm;
    }

    @Override
    public String name() {
        return "Fortify SSC";
    }

    @Override
    public String description() {
        return "Pushes Dependency-Track findings to Software Security Center";
    }

    @Override
    public boolean isEnabled() {
        final ConfigProperty enabled = qm.getConfigProperty(FORTIFY_SSC_ENABLED.getGroupName(), FORTIFY_SSC_ENABLED.getPropertyName());
        if (enabled != null && Boolean.valueOf(enabled.getPropertyValue())) {
            return true;
        }
        return false;
    }

    @Override
    public boolean isProjectConfigured(Project project) {
        final ProjectProperty applicationId = qm.getProjectProperty(project, FORTIFY_SSC_ENABLED.getGroupName(), APPID_PROPERTY);
        if (applicationId != null && applicationId.getPropertyValue() != null) {
            return true;
        }
        return false;
    }

    @Override
    public InputStream process(Project project, List<Finding> findings) {
        final JSONObject fpf = new FindingPackagingFormat(project.getUuid(), findings).getDocument();
        return new ByteArrayInputStream(fpf.toString(2).getBytes());
    }

    @Override
    public void upload(Project project, Object payload) {
        final ConfigProperty sscUrl = qm.getConfigProperty(FORTIFY_SSC_URL.getGroupName(), FORTIFY_SSC_URL.getPropertyName());
        final ConfigProperty username = qm.getConfigProperty(FORTIFY_SSC_USERNAME.getGroupName(), FORTIFY_SSC_USERNAME.getPropertyName());
        final ConfigProperty password = qm.getConfigProperty(FORTIFY_SSC_PASSWORD.getGroupName(), FORTIFY_SSC_PASSWORD.getPropertyName());
        final ProjectProperty applicationId = qm.getProjectProperty(project, FORTIFY_SSC_ENABLED.getGroupName(), APPID_PROPERTY);
        try {
            final FortifySscClient client = new FortifySscClient(this, new URL(sscUrl.getPropertyValue()));
            final String token = client.generateOneTimeUploadToken(
                    username.getPropertyValue(),
                    DataEncryption.decryptAsString(password.getPropertyValue()));
            if (token != null) {
                client.uploadDependencyTrackFindings(token, applicationId.getPropertyValue(), (InputStream)payload);
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred attempting to upload findings to Fortify Software Security Center", e);
            handleException(LOGGER, e);
        }
    }

    @Override
    public void complete() {
        // nothing to do
    }
}
