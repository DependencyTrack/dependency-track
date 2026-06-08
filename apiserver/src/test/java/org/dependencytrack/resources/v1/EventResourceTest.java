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
package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.ExistsWorkflowRunRequest;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class EventResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(EventResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(DEX_ENGINE_MOCK).to(DexEngine.class);
                        }
                    }));

    @AfterEach
    void afterEach() {
        Mockito.reset(DEX_ENGINE_MOCK);
    }

    @Test
    void isTokenBeingProcessedDexRunByIdTest() {
        final var runId = UUID.fromString("6214c0c2-660c-4615-8b3a-174a64e4abe4");
        final var runMetadata = new WorkflowRunMetadata(
                runId,
                null,
                "analyze-project",
                1,
                null,
                "default",
                WorkflowRunStatus.RUNNING,
                null,
                0,
                null,
                null,
                Instant.now(),
                Instant.now(),
                null,
                null);
        doReturn(false).when(DEX_ENGINE_MOCK).existsRun(any(ExistsWorkflowRunRequest.class));
        doReturn(runMetadata).when(DEX_ENGINE_MOCK).getRunMetadataById(runId);

        final Response response = jersey
                .target(V1_EVENT + "/token/6214c0c2-660c-4615-8b3a-174a64e4abe4")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "processing": true
                }
                """);
    }

    @Test
    void isTokenBeingProcessedDexRunByLabelTest() {
        final var bomUploadToken = UUID.fromString("2ff20ad6-587c-4db6-8788-cca7a9b0dc1b");

        doReturn(null).when(DEX_ENGINE_MOCK).getRunMetadataById(bomUploadToken);
        doReturn(true).when(DEX_ENGINE_MOCK).existsRun(any(ExistsWorkflowRunRequest.class));

        final Response response = jersey
                .target(V1_EVENT + "/token/2ff20ad6-587c-4db6-8788-cca7a9b0dc1b")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "processing": true
                }
                """);
    }

    @Test
    void isTokenBeingProcessedNotExistsTest() {
        doReturn(null).when(DEX_ENGINE_MOCK).getRunMetadataById(any());
        doReturn(false).when(DEX_ENGINE_MOCK).existsRun(any(ExistsWorkflowRunRequest.class));

        final Response response = jersey
                .target(V1_EVENT + "/token/089dcdbe-31cf-489a-a8f3-0743ea7f3cc5")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "processing": false
                }
                """);
    }

}
