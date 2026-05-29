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
package org.dependencytrack.e2e;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import org.dependencytrack.e2e.api.model.BomUploadRequest;
import org.dependencytrack.e2e.api.model.EventProcessingResponse;
import org.dependencytrack.e2e.api.model.EventTokenResponse;
import org.dependencytrack.e2e.api.model.Project;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class BomUploadS3FileStorageE2ET extends AbstractE2ET {

    private static final DockerImageName S3MOCK_IMAGE =
            DockerImageName.parse("adobe/s3mock").withTag("5.0.0");

    private S3MockContainer s3MockContainer;

    @Override
    @BeforeEach
    void beforeEach() throws Exception {
        s3MockContainer = new S3MockContainer(S3MOCK_IMAGE)
                .withInitialBuckets("dtrack")
                .withNetwork(internalNetwork)
                .withNetworkAliases("s3mock");
        s3MockContainer.start();

        super.beforeEach();
    }

    @Override
    protected void customizeApiServerContainer(GenericContainer<?> container) {
        container
                .withEnv("DT_FILE_STORAGE_PROVIDER", "s3")
                .withEnv("DT_FILE_STORAGE_S3_ENDPOINT", "http://s3mock:9090")
                .withEnv("DT_FILE_STORAGE_S3_BUCKET", "dtrack")
                .withEnv("DT_FILE_STORAGE_S3_ACCESS_KEY", "foo")
                .withEnv("DT_FILE_STORAGE_S3_SECRET_KEY", "bar")
                // Provide a hardcoded KEK to prevent the API server from generating a KEK keyset on disk.
                .withEnv("DT_SECRET_MANAGEMENT_DATABASE_KEK", "Ccbo1y2QTKVHZbANVb/ER5yvTn5yZe5UtIpZ+eRSnTg=")
                // Point the data directory at a read-only mount.
                // If the API server were to write BOM files to local disk, the write would fail.
                // A successful BOM upload and processing thus proves that S3 storage is in use,
                // without having to race against the API server deleting the temporary file again.
                .withTmpFs(Map.of("/data", "ro"));
    }

    @AfterEach
    void afterEachS3() {
        Optional.ofNullable(s3MockContainer).ifPresent(GenericContainer::stop);
    }

    @Test
    void shouldUploadAndProcessBomWhenS3FileStorageConfigured() throws Exception {
        final byte[] bomBytes = getClass().getResourceAsStream("/dtrack-apiserver-4.5.0.bom.json").readAllBytes();
        final String bomBase64 = Base64.getEncoder().encodeToString(bomBytes);

        final EventTokenResponse response = apiClient.uploadBom(
                new BomUploadRequest("foo", "bar", true, bomBase64));
        assertThat(response.token()).isNotEmpty();

        await("BOM processing")
                .atMost(Duration.ofSeconds(15))
                .pollDelay(Duration.ofMillis(250))
                .untilAsserted(() -> {
                    final EventProcessingResponse processingResponse =
                            apiClient.isEventBeingProcessed(response.token());
                    assertThat(processingResponse.processing()).isFalse();
                });

        final Project project = apiClient.lookupProject("foo", "bar");
        assertThat(project).isNotNull();
    }

}
