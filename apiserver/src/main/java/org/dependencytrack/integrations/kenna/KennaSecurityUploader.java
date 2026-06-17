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
package org.dependencytrack.integrations.kenna;

import alpine.model.ConfigProperty;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.common.MultipartBodyPublisher;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.PortfolioFindingUploader;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.secret.management.SecretManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import javax.jdo.Query;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_API_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_CONNECTOR_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_TOKEN;

public class KennaSecurityUploader extends AbstractIntegrationPoint implements PortfolioFindingUploader {

    private static final Logger LOGGER = LoggerFactory.getLogger(KennaSecurityUploader.class);
    private static final String ASSET_EXTID_PROPERTY = "kenna.asset.external_id";

    private final HttpClient httpClient;
    private final SecretManager secretManager;
    private String connectorId;

    public KennaSecurityUploader(HttpClient httpClient, SecretManager secretManager) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
        this.secretManager = requireNonNull(secretManager, "secretManager must not be null");
    }

    @Override
    public String name() {
        return "Kenna Security";
    }

    @Override
    public String description() {
        return "Pushes Dependency-Track findings to Kenna Security";
    }

    @Override
    public boolean isEnabled() {
        final ConfigProperty connector = qm.getConfigProperty(KENNA_CONNECTOR_ID.getGroupName(), KENNA_CONNECTOR_ID.getPropertyName());
        if (qm.isEnabled(KENNA_ENABLED) && connector != null && connector.getPropertyValue() != null) {
            connectorId = connector.getPropertyValue();
            return true;
        }
        return false;
    }

    @Override
    public InputStream process() {
        LOGGER.debug("Processing...");
        final KennaDataTransformer kdi = new KennaDataTransformer(qm);

        List<Project> projects = fetchNextProjectBatch(qm, null);
        while (!projects.isEmpty()) {
            if (Thread.currentThread().isInterrupted()) {
                LOGGER.warn("Interrupted before all projects could be processed");
                break;
            }

            for (final Project project : projects) {
                try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, project.getUuid().toString());
                     var _ = MDC.putCloseable(MDC_PROJECT_NAME, project.getName());
                     var _ = MDC.putCloseable(MDC_PROJECT_VERSION, project.getVersion())) {
                    if (Thread.currentThread().isInterrupted()) {
                        LOGGER.warn("Interrupted before project could be processed");
                        break;
                    }

                    final ProjectProperty externalId = qm.getProjectProperty(project, KENNA_ENABLED.getGroupName(), ASSET_EXTID_PROPERTY);
                    if (externalId != null && externalId.getPropertyValue() != null) {
                        LOGGER.debug("Transforming findings to KDI format");
                        kdi.process(project, externalId.getPropertyValue());
                    }
                }
            }

            qm.getPersistenceManager().evictAll(false, Project.class);
            projects = fetchNextProjectBatch(qm, projects.getLast().getId());
        }

        return new ByteArrayInputStream(kdi.generate().toString().getBytes());
    }

    @Override
    public void upload(final InputStream payload) {
        LOGGER.debug("Uploading payload to KennaSecurity");
        final ConfigProperty apiUrlProperty = qm.getConfigProperty(KENNA_API_URL.getGroupName(), KENNA_API_URL.getPropertyName());
        final ConfigProperty tokenProperty = qm.getConfigProperty(KENNA_TOKEN.getGroupName(), KENNA_TOKEN.getPropertyName());
        if (tokenProperty == null) {
            LOGGER.warn("Kenna Security token not specified. Aborting");
            return;
        }
        final String tokenSecretName = StringUtils.trimToNull(tokenProperty.getPropertyValue());
        if (tokenSecretName == null) {
            LOGGER.warn("Kenna Security token not specified. Aborting");
            return;
        }
        try {
            final String tokenValue = secretManager.getSecretValue(tokenSecretName);
            if (tokenValue == null) {
                LOGGER.warn("Kenna Security secret '%s' could not be resolved. Aborting".formatted(tokenSecretName));
                return;
            }

            final var multipart = new MultipartBodyPublisher()
                    .addFormField("run", "true")
                    .addFilePart("file", "findings.json", payload, "application/json");

            final var request = HttpRequest.newBuilder()
                    .uri(URI.create("%s/connectors/%s/data_file".formatted(apiUrlProperty.getPropertyValue(), connectorId)))
                    .header("X-Risk-Token", tokenValue)
                    .header("Accept", "application/json")
                    .header("Content-Type", multipart.contentType())
                    .POST(multipart.build())
                    .build();

            final HttpResponse<String> response = httpClient
                    .send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200 && response.body() != null) {
                final JsonNode root = Mappers.jsonMapper().readTree(response.body());
                if ("true".equals(root.path("success").asText())) {
                    LOGGER.debug("Successfully uploaded KDI");
                    return;
                }
                LOGGER.warn("An unexpected response was received uploading findings to Kenna Security");
            } else {
                handleUnexpectedHttpResponse(LOGGER, request.uri().toString(), response.statusCode(), response.body());
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred attempting to upload findings to Kenna Security", e);
        }
    }

    private List<Project> fetchNextProjectBatch(final QueryManager qm, final Long lastId) {
        // TODO: Shouldn't we only select active projects here?
        //  This is existing behavior so we can't just change it.

        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        if (lastId != null) {
            query.setFilter("id > :lastId");
            query.setParameters(lastId);
        }
        query.setOrdering("id asc");
        query.setRange(0, 100);

        try {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

}
