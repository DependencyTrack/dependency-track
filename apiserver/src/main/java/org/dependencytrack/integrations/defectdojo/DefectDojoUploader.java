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

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.FindingPackagingFormat;
import org.dependencytrack.integrations.ProjectFindingUploader;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectPropertyDao;
import org.dependencytrack.persistence.jdbi.ProjectPropertyDao.ProjectPropertyRow;
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
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class DefectDojoUploader extends AbstractIntegrationPoint implements ProjectFindingUploader {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefectDojoUploader.class);
    private static final String ENGAGEMENTID_PROPERTY = "defectdojo.engagementId";
    private static final String REIMPORT_PROPERTY = "defectdojo.reimport";
    private static final String DO_NOT_REACTIVATE_PROPERTY = "defectdojo.doNotReactivate";
    private static final String VERIFIED_PROPERTY = "defectdojo.verified";
    private static final String TEST_TITLE_PROPERTY = "defectdojo.testTitle";
    private static final String GROUP_BY_PROPERTY = "defectdojo.groupBy";

    private final HttpClient httpClient;
    private final SecretManager secretManager;

    public DefectDojoUploader(HttpClient httpClient, SecretManager secretManager) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
        this.secretManager = requireNonNull(secretManager, "secretManager must not be null");
    }

    private boolean isReimportConfigured(final Project project) {
        return Boolean.parseBoolean(
                getProjectPropertyValue(project, DEFECTDOJO_ENABLED.getGroupName(), REIMPORT_PROPERTY));
    }

    private boolean isDoNotReactivateConfigured(final Project project) {
        return Boolean.parseBoolean(
                getProjectPropertyValue(project, DEFECTDOJO_ENABLED.getGroupName(), DO_NOT_REACTIVATE_PROPERTY));
    }

    private boolean isVerifiedConfigured(final Project project) {
        final ProjectPropertyRow verified = withJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .getProperty(project.getUuid(), DEFECTDOJO_ENABLED.getGroupName(), VERIFIED_PROPERTY));
        if (verified != null) {
            return Boolean.parseBoolean(verified.propertyValue());
        } else {
            // Defaults to true for backward compatibility with old behavior where "verified" was always true
            return true;
        }
    }

    private @Nullable String getTestTitle(final Project project) {
        return getProjectPropertyValue(project, DEFECTDOJO_ENABLED.getGroupName(), TEST_TITLE_PROPERTY);
    }

    @Nullable
    String getGroupBy(final Project project) {
        return getProjectPropertyValue(project, DEFECTDOJO_ENABLED.getGroupName(), GROUP_BY_PROPERTY);
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
        return isConfigEnabled(DEFECTDOJO_ENABLED);
    }

    @Override
    public boolean isProjectConfigured(final Project project) {
        return getProjectPropertyValue(project, DEFECTDOJO_ENABLED.getGroupName(), ENGAGEMENTID_PROPERTY) != null;
    }

    @Override
    public InputStream process(final Project project, final List<Finding> findings) {
        final String fpf = new FindingPackagingFormat(project.getUuid(), findings).getDocument();
        return new ByteArrayInputStream(fpf.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void upload(final Project project, final InputStream payload) {
        final String defectDojoUrl = getConfigValue(DEFECTDOJO_URL);
        final String apiKey = getConfigValue(DEFECTDOJO_API_KEY);
        if (apiKey == null) {
            LOGGER.warn("DefectDojo API key not specified. Aborting");
            return;
        }
        final String apiKeySecretName = StringUtils.trimToNull(apiKey);
        if (apiKeySecretName == null) {
            LOGGER.warn("DefectDojo API key not specified. Aborting");
            return;
        }
        final boolean globalReimportEnabled = isConfigEnabled(DEFECTDOJO_REIMPORT_ENABLED);
        final String engagementId =
                getProjectPropertyValue(project, DEFECTDOJO_ENABLED.getGroupName(), ENGAGEMENTID_PROPERTY);
        final boolean verifyFindings = isVerifiedConfigured(project);
        final String testTitle = getTestTitle(project);
        final String groupBy = getGroupBy(project);
        try {
            final String apiKeyValue = secretManager.getSecretValue(apiKeySecretName);
            if (apiKeyValue == null) {
                LOGGER.warn(
                        "DefectDojo API key secret '%s' could not be resolved. Aborting".formatted(apiKeySecretName));
                return;
            }
            final DefectDojoClient client = new DefectDojoClient(
                    httpClient, this, URI.create(defectDojoUrl).toURL());
            if (isReimportConfigured(project) || globalReimportEnabled) {
                final ArrayList<String> testsIds = client.getDojoTestIds(apiKeyValue, engagementId);
                final String testId = client.getDojoTestId(engagementId, testsIds, testTitle);
                LOGGER.debug("Found existing test Id: {}", testId);
                if (testId.equals("")) {
                    client.uploadDependencyTrackFindings(
                            apiKeyValue, engagementId, payload, verifyFindings, testTitle, groupBy);
                } else {
                    client.reimportDependencyTrackFindings(
                            apiKeyValue,
                            engagementId,
                            payload,
                            testId,
                            isDoNotReactivateConfigured(project),
                            verifyFindings,
                            testTitle,
                            groupBy);
                }
            } else {
                client.uploadDependencyTrackFindings(
                        apiKeyValue, engagementId, payload, verifyFindings, testTitle, groupBy);
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred attempting to upload findings to DefectDojo", e);
            handleException(LOGGER, e);
        }
    }
}
