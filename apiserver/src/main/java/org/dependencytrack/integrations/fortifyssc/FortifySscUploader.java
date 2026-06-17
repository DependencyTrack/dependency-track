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
package org.dependencytrack.integrations.fortifyssc;

import alpine.model.ConfigProperty;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.FindingPackagingFormat;
import org.dependencytrack.integrations.ProjectFindingUploader;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.secret.management.SecretManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.model.ConfigPropertyConstants.FORTIFY_SSC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.FORTIFY_SSC_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.FORTIFY_SSC_URL;

public class FortifySscUploader extends AbstractIntegrationPoint implements ProjectFindingUploader {

    private static final Logger LOGGER = LoggerFactory.getLogger(FortifySscUploader.class);
    private static final String APPID_PROPERTY = "fortify.ssc.applicationId";

    private final HttpClient httpClient;
    private final SecretManager secretManager;

    public FortifySscUploader(HttpClient httpClient, SecretManager secretManager) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
        this.secretManager = requireNonNull(secretManager, "secretManager must not be null");
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
        return enabled != null && Boolean.valueOf(enabled.getPropertyValue());
    }

    @Override
    public boolean isProjectConfigured(final Project project) {
        final ProjectProperty applicationId = qm.getProjectProperty(project, FORTIFY_SSC_ENABLED.getGroupName(), APPID_PROPERTY);
        return applicationId != null && applicationId.getPropertyValue() != null;
    }

    @Override
    public InputStream process(final Project project, final List<Finding> findings) {
        final String fpf = new FindingPackagingFormat(project.getUuid(), findings).getDocument();
        return new ByteArrayInputStream(fpf.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void upload(final Project project, final InputStream payload) {
        final ConfigProperty sscUrl = qm.getConfigProperty(FORTIFY_SSC_URL.getGroupName(), FORTIFY_SSC_URL.getPropertyName());
        final ConfigProperty citoken = qm.getConfigProperty(FORTIFY_SSC_TOKEN.getGroupName(), FORTIFY_SSC_TOKEN.getPropertyName());
        final ProjectProperty applicationId = qm.getProjectProperty(project, FORTIFY_SSC_ENABLED.getGroupName(), APPID_PROPERTY);
        if (citoken == null) {
            LOGGER.warn("Fortify SSC token not specified. Aborting");
            return;
        }
        final String tokenSecretName = StringUtils.trimToNull(citoken.getPropertyValue());
        if (tokenSecretName == null) {
            LOGGER.warn("Fortify SSC token not specified. Aborting");
            return;
        }
        try {
            final FortifySscClient client = new FortifySscClient(httpClient, this, URI.create(sscUrl.getPropertyValue()).toURL());
            final String tokenValue = secretManager.getSecretValue(tokenSecretName);
            if (tokenValue == null) {
                LOGGER.warn("Fortify SSC secret '%s' could not be resolved. Aborting".formatted(tokenSecretName));
                return;
            }
            final String token = client.generateOneTimeUploadToken(tokenValue);
            if (token != null) {
                client.uploadDependencyTrackFindings(token, applicationId.getPropertyValue(), payload);
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred attempting to upload findings to Fortify Software Security Center", e);
            handleException(LOGGER, e);
        }
    }
}
