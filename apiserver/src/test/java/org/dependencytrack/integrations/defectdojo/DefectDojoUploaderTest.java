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

import alpine.model.IConfigProperty;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectPropertyDao;
import org.dependencytrack.persistence.jdbi.ProjectPropertyDao.ProjectPropertyRow;
import org.dependencytrack.secret.management.SecretManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_API_KEY;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_REIMPORT_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_URL;
import static org.dependencytrack.persistence.jdbi.ConfigPropertyTestUtil.createConfigProperty;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DefectDojoUploaderTest extends PersistenceCapableTest {

    private static HttpClient httpClient;
    private static SecretManager secretManager;

    @BeforeAll
    static void beforeEach() {
        httpClient = HttpClient.newHttpClient();
        secretManager = mock(SecretManager.class);
        doAnswer(invocation -> invocation.getArgument(0)).when(secretManager).getSecretValue(anyString());
    }

    @AfterAll
    static void afterEach() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

    @Test
    void testIntegrationMetadata() {
        DefectDojoUploader extension = new DefectDojoUploader(httpClient, secretManager);
        Assertions.assertEquals("DefectDojo", extension.name());
        Assertions.assertEquals("Pushes Dependency-Track findings to DefectDojo", extension.description());
    }

    @Test
    void testIntegrationEnabledCases() {
        createConfigProperty(DEFECTDOJO_ENABLED, "true");
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, null, false);
        useJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .createProperty(
                        project.getUuid(),
                        new ProjectPropertyRow(
                                DEFECTDOJO_ENABLED.getGroupName(),
                                "defectdojo.engagementId",
                                "12345",
                                IConfigProperty.PropertyType.STRING,
                                null)));
        DefectDojoUploader extension = new DefectDojoUploader(httpClient, secretManager);
        extension.setQueryManager(qm);
        Assertions.assertTrue(extension.isEnabled());
        Assertions.assertTrue(extension.isProjectConfigured(project));
    }

    @Test
    void testIntegrationDisabledCases() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, null, false);
        DefectDojoUploader extension = new DefectDojoUploader(httpClient, secretManager);
        extension.setQueryManager(qm);
        Assertions.assertFalse(extension.isEnabled());
        Assertions.assertFalse(extension.isProjectConfigured(project));
    }

    @Test
    void testGetGroupByReturnsNullWhenNotConfigured() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, null, false);
        DefectDojoUploader extension = new DefectDojoUploader(httpClient, secretManager);
        extension.setQueryManager(qm);
        Assertions.assertNull(extension.getGroupBy(project));
    }

    @Test
    void testGetGroupByReturnsValueWhenConfigured() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, null, false);
        useJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .createProperty(
                        project.getUuid(),
                        new ProjectPropertyRow(
                                DEFECTDOJO_ENABLED.getGroupName(),
                                "defectdojo.groupBy",
                                "component_name",
                                IConfigProperty.PropertyType.STRING,
                                null)));
        DefectDojoUploader extension = new DefectDojoUploader(httpClient, secretManager);
        extension.setQueryManager(qm);
        Assertions.assertEquals("component_name", extension.getGroupBy(project));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testLookupFailureDoesNotUploadFindings() throws Exception {
        createConfigProperty(DEFECTDOJO_URL, "http://localhost:12345");
        createConfigProperty(DEFECTDOJO_API_KEY, "test-token");
        createConfigProperty(DEFECTDOJO_REIMPORT_ENABLED, "true");
        Project project = qm.createProject("Lookup failure", null, "1.0", null, null, null, null, false);
        useJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .createProperty(
                        project.getUuid(),
                        new ProjectPropertyRow(
                                DEFECTDOJO_ENABLED.getGroupName(),
                                "defectdojo.engagementId",
                                "12345",
                                IConfigProperty.PropertyType.STRING,
                                null)));
        HttpClient failingClient = mock(HttpClient.class);
        HttpResponse<String> unavailable = mock(HttpResponse.class);
        when(unavailable.statusCode()).thenReturn(503);
        when(unavailable.body()).thenReturn("Service unavailable");
        when(failingClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(unavailable);
        DefectDojoUploader extension = new DefectDojoUploader(failingClient, secretManager);
        extension.setQueryManager(qm);

        extension.upload(project, new ByteArrayInputStream("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8)));

        verify(failingClient)
                .send(argThat(request -> request.method().equals("GET")), any(HttpResponse.BodyHandler.class));
        verify(failingClient, never())
                .send(argThat(request -> request.method().equals("POST")), any(HttpResponse.BodyHandler.class));
    }
}
