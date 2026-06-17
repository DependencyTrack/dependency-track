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
package org.dependencytrack.integrations.defectdojo;

import alpine.model.ConfigProperty;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.FindingPackagingFormat;
import org.dependencytrack.integrations.ProjectFindingUploader;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.secret.management.SecretManager;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_API_KEY;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_REIMPORT_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_URL;

public class DefectDojoUploader extends AbstractIntegrationPoint implements ProjectFindingUploader {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefectDojoUploader.class);
    private static final String ENGAGEMENTID_PROPERTY = "defectdojo.engagementId";
    private static final String REIMPORT_PROPERTY = "defectdojo.reimport";
    private static final String DO_NOT_REACTIVATE_PROPERTY = "defectdojo.doNotReactivate";
    private static final String VERIFIED_PROPERTY = "defectdojo.verified";
    private static final String TEST_TITLE_PROPERTY = "defectdojo.testTitle";

    private final HttpClient httpClient;
    private final SecretManager secretManager;

    public DefectDojoUploader(HttpClient httpClient, SecretManager secretManager) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
        this.secretManager = requireNonNull(secretManager, "secretManager must not be null");
    }

    private boolean isReimportConfigured(final Project project) {
        final ProjectProperty reimport = qm.getProjectProperty(project, DEFECTDOJO_ENABLED.getGroupName(), REIMPORT_PROPERTY);
        if (reimport != null) {
            return Boolean.parseBoolean(reimport.getPropertyValue());
        } else {
            return false;
        }
    }

    private boolean isDoNotReactivateConfigured(final Project project) {
        final ProjectProperty reactivate = qm.getProjectProperty(project, DEFECTDOJO_ENABLED.getGroupName(), DO_NOT_REACTIVATE_PROPERTY);
        if (reactivate != null) {
            return Boolean.parseBoolean(reactivate.getPropertyValue());
        } else {
            return false;
        }
    }

    private boolean isVerifiedConfigured(final Project project) {
        final ProjectProperty verified = qm.getProjectProperty(project, DEFECTDOJO_ENABLED.getGroupName(), VERIFIED_PROPERTY);
        if (verified != null) {
            return Boolean.parseBoolean(verified.getPropertyValue());
        } else {
            // Defaults to true for backward compatibility with old behavior where "verified" was always true
            return true;
        }
    }

    private @Nullable String getTestTitle(final Project project) {
        final ProjectProperty testName = qm.getProjectProperty(project, DEFECTDOJO_ENABLED.getGroupName(), TEST_TITLE_PROPERTY);
        if (testName != null && testName.getPropertyValue() != null) {
            return testName.getPropertyValue();
        }
        return null;
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
        final String fpf = new FindingPackagingFormat(project.getUuid(), findings).getDocument();
        return new ByteArrayInputStream(fpf.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void upload(final Project project, final InputStream payload) {
        final ConfigProperty defectDojoUrl = qm.getConfigProperty(DEFECTDOJO_URL.getGroupName(), DEFECTDOJO_URL.getPropertyName());
        final ConfigProperty apiKeyProperty = qm.getConfigProperty(DEFECTDOJO_API_KEY.getGroupName(), DEFECTDOJO_API_KEY.getPropertyName());
        if (apiKeyProperty == null) {
            LOGGER.warn("DefectDojo API key not specified. Aborting");
            return;
        }
        final String apiKeySecretName = StringUtils.trimToNull(apiKeyProperty.getPropertyValue());
        if (apiKeySecretName == null) {
            LOGGER.warn("DefectDojo API key not specified. Aborting");
            return;
        }
        final boolean globalReimportEnabled = qm.isEnabled(DEFECTDOJO_REIMPORT_ENABLED);
        final ProjectProperty engagementId = qm.getProjectProperty(project, DEFECTDOJO_ENABLED.getGroupName(), ENGAGEMENTID_PROPERTY);
        final boolean verifyFindings = isVerifiedConfigured(project);
        try {
            final String apiKeyValue = secretManager.getSecretValue(apiKeySecretName);
            if (apiKeyValue == null) {
                LOGGER.warn("DefectDojo API key secret '%s' could not be resolved. Aborting".formatted(apiKeySecretName));
                return;
            }
            final String testTitle = getTestTitle(project);
            final DefectDojoClient client = new DefectDojoClient(httpClient, this, URI.create(defectDojoUrl.getPropertyValue()).toURL());
            if (isReimportConfigured(project) || globalReimportEnabled) {
                final ArrayList<String> testsIds = client.getDojoTestIds(apiKeyValue, engagementId.getPropertyValue());
                final String testId = client.getDojoTestId(engagementId.getPropertyValue(), testsIds, testTitle);
                LOGGER.debug("Found existing test Id: {}", testId);
                if (testId.equals("")) {
                    client.uploadDependencyTrackFindings(
                            apiKeyValue,
                            engagementId.getPropertyValue(),
                            payload,
                            verifyFindings,
                            testTitle);
                } else {
                    client.reimportDependencyTrackFindings(
                            apiKeyValue,
                            engagementId.getPropertyValue(),
                            payload,
                            testId,
                            isDoNotReactivateConfigured(project),
                            verifyFindings,
                            testTitle);
                }
            } else {
                client.uploadDependencyTrackFindings(
                        apiKeyValue,
                        engagementId.getPropertyValue(),
                        payload,
                        verifyFindings,
                        testTitle);
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred attempting to upload findings to DefectDojo", e);
            handleException(LOGGER, e);
        }
    }
}
