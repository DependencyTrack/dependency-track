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

import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.PortfolioFindingUploader;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.DebugDataEncryption;
import org.json.JSONObject;
import org.slf4j.MDC;

import javax.jdo.Query;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_API_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_CONNECTOR_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_TOKEN;

public class KennaSecurityUploader extends AbstractIntegrationPoint implements PortfolioFindingUploader {

    private static final Logger LOGGER = Logger.getLogger(KennaSecurityUploader.class);
    private static final String ASSET_EXTID_PROPERTY = "kenna.asset.external_id";

    private String connectorId;

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
                try (var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, project.getUuid().toString());
                     var ignoredMdcProjectName = MDC.putCloseable(MDC_PROJECT_NAME, project.getName());
                     var ignoredMdcProjectVersion = MDC.putCloseable(MDC_PROJECT_VERSION, project.getVersion())) {
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
        try {
            final String token = DebugDataEncryption.decryptAsString(tokenProperty.getPropertyValue());
            HttpPost request = new HttpPost("%s/connectors/%s/data_file".formatted(apiUrlProperty.getPropertyValue(), connectorId));
            request.addHeader("X-Risk-Token", token);
            request.addHeader("accept", "application/json");
            List<NameValuePair> nameValuePairList = new ArrayList<>();
            nameValuePairList.add(new BasicNameValuePair("run", "true"));
            request.setEntity(new UrlEncodedFormEntity(nameValuePairList, StandardCharsets.UTF_8));
            HttpEntity data = MultipartEntityBuilder.create().setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                    .addBinaryBody("file", payload, ContentType.APPLICATION_JSON, "findings.json")
                    .build();
            request.setEntity(data);
            try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK && response.getEntity() != null) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    final JSONObject root = new JSONObject(responseString);
                    if (root.getString("success").equals("true")) {
                        LOGGER.debug("Successfully uploaded KDI");
                        return;
                    }
                    LOGGER.warn("An unexpected response was received uploading findings to Kenna Security");
                } else {
                    handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
                }
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
