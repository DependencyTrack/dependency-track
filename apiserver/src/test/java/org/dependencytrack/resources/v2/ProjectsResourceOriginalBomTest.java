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
package org.dependencytrack.resources.v2;

import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Project;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;

import jakarta.ws.rs.core.Response;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.NoSuchFileException;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.resources.v2.OpenApiValidationClientResponseFilter.DISABLE_OPENAPI_VALIDATION;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class ProjectsResourceOriginalBomTest extends ResourceTest {

    private static final FileStorage FILE_STORAGE_MOCK = mock(FileStorage.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig().register(new AbstractBinder() {
        @Override
        protected void configure() {
            bind(FILE_STORAGE_MOCK).to(FileStorage.class);
        }
    }));

    @AfterEach
    void afterEach() {
        Mockito.reset(FILE_STORAGE_MOCK);
    }

    @Test
    void getProjectOriginalBomShouldReturnNewestRetainedBom() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("Acme Application", null, "1.0", null, null, null, null, false);

        final FileMetadata olderFileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///project-original-bom-older.json")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("older")
                .build();

        persistBom(project, Instant.parse("2026-01-01T00:00:00Z"), "1.5", olderFileMetadata.toByteArray());

        final byte[] expectedBomBytes = "newest retained BOM".getBytes(StandardCharsets.UTF_8);
        final FileMetadata expectedFileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///project-original-bom-newest.json")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("newest")
                .build();

        persistBom(project, Instant.parse("2026-01-02T00:00:00Z"), "1.6", expectedFileMetadata.toByteArray());

        persistBomWithoutMetadata(project, Instant.parse("2026-01-03T00:00:00Z"), "1.6");

        doReturn(new ByteArrayInputStream(expectedBomBytes))
                .when(FILE_STORAGE_MOCK)
                .get(expectedFileMetadata);

        final Response response = jersey.target("/projects/%s/bom/original".formatted(project.getUuid()))
                .request()
                .property(DISABLE_OPENAPI_VALIDATION, "true")
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMediaType().toString()).isEqualTo("application/vnd.cyclonedx+json");
        assertThat(response.getHeaderString("Content-Disposition")).isEqualTo("attachment; filename=\"bom.json\"");
        assertThat(response.readEntity(byte[].class)).containsExactly(expectedBomBytes);

        verify(FILE_STORAGE_MOCK).get(expectedFileMetadata);
    }

    @Test
    void getProjectOriginalBomShouldReturnNotFoundWhenMetadataIsAbsent() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("Acme Application", null, "1.0", null, null, null, null, false);

        persistBomWithoutMetadata(project, Instant.parse("2026-01-01T00:00:00Z"), "1.6");

        final Response response = jersey.target("/projects/%s/bom/original".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(404);

        verifyNoInteractions(FILE_STORAGE_MOCK);
    }

    @Test
    void getProjectOriginalBomShouldReturnNotFoundWhenFileIsMissing() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("Acme Application", null, "1.0", null, null, null, null, false);

        final FileMetadata fileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///missing-original-bom.json")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("missing")
                .build();

        persistBom(project, Instant.parse("2026-01-01T00:00:00Z"), "1.6", fileMetadata.toByteArray());

        doThrow(new NoSuchFileException(fileMetadata.getLocation()))
                .when(FILE_STORAGE_MOCK)
                .get(fileMetadata);

        final Response response = jersey.target("/projects/%s/bom/original".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(404);

        verify(FILE_STORAGE_MOCK).get(fileMetadata);
    }

    @Test
    void getProjectOriginalBomShouldReturnNotFoundWhenProjectDoesNotExist() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final UUID projectUuid = UUID.randomUUID();

        final Response response = jersey.target("/projects/%s/bom/original".formatted(projectUuid))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(404);

        verifyNoInteractions(FILE_STORAGE_MOCK);
    }

    @Test
    void getProjectOriginalBomShouldReturnForbiddenWithoutProjectAccess() {
        enablePortfolioAccessControl();
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("Acme Application", null, "1.0", null, null, null, null, false);

        final Response response = jersey.target("/projects/%s/bom/original".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(403);

        verifyNoInteractions(FILE_STORAGE_MOCK);
    }

    @Test
    void getProjectOriginalBomShouldReturnForbiddenWithoutPermission() {
        initializeWithPermissions();

        final Response response = jersey.target("/projects/%s/bom/original".formatted(UUID.randomUUID()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(403);

        verifyNoInteractions(FILE_STORAGE_MOCK);
    }

    @Test
    void getProjectOriginalBomShouldReturnXmlBom() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("Acme Application", null, "1.0", null, null, null, null, false);

        final byte[] expectedBomBytes = "<bom>retained XML BOM</bom>".getBytes(StandardCharsets.UTF_8);
        final FileMetadata fileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///project-original-bom.xml")
                .setMediaType("application/vnd.cyclonedx+xml")
                .setSha256Digest("xml")
                .build();

        persistBom(project, Instant.parse("2026-01-01T00:00:00Z"), "1.6", fileMetadata.toByteArray());

        doReturn(new ByteArrayInputStream(expectedBomBytes))
                .when(FILE_STORAGE_MOCK)
                .get(fileMetadata);

        final Response response = jersey.target("/projects/%s/bom/original".formatted(project.getUuid()))
                .request()
                .property(DISABLE_OPENAPI_VALIDATION, "true")
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getMediaType().toString()).isEqualTo("application/vnd.cyclonedx+xml");
        assertThat(response.getHeaderString("Content-Disposition")).isEqualTo("attachment; filename=\"bom.xml\"");
        assertThat(response.readEntity(byte[].class)).containsExactly(expectedBomBytes);

        verify(FILE_STORAGE_MOCK).get(fileMetadata);
    }

    @Test
    void getProjectOriginalBomShouldReturnServerErrorWhenMetadataIsMalformed() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("Acme Application", null, "1.0", null, null, null, null, false);

        persistBom(project, Instant.parse("2026-01-01T00:00:00Z"), "1.6", new byte[] {(byte) 0x80});

        final Response response = jersey.target("/projects/%s/bom/original".formatted(project.getUuid()))
                .request()
                .property(DISABLE_OPENAPI_VALIDATION, "true")
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(500);

        verifyNoInteractions(FILE_STORAGE_MOCK);
    }

    @Test
    void getProjectOriginalBomShouldReturnServerErrorWhenStorageFails() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Project project = qm.createProject("Acme Application", null, "1.0", null, null, null, null, false);

        final FileMetadata fileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///unavailable-original-bom.json")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("unavailable")
                .build();

        persistBom(project, Instant.parse("2026-01-01T00:00:00Z"), "1.6", fileMetadata.toByteArray());

        doThrow(new IOException("Storage unavailable")).when(FILE_STORAGE_MOCK).get(fileMetadata);

        final Response response = jersey.target("/projects/%s/bom/original".formatted(project.getUuid()))
                .request()
                .property(DISABLE_OPENAPI_VALIDATION, "true")
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(500);

        verify(FILE_STORAGE_MOCK).get(fileMetadata);
    }

    private Bom persistBom(
            final Project project,
            final Instant importedAt,
            final String specVersion,
            final byte[] originalFileMetadata) {
        final Bom bom = persistBomWithoutMetadata(project, importedAt, specVersion);
        bom.setOriginalFileMetadata(originalFileMetadata);
        return bom;
    }

    private Bom persistBomWithoutMetadata(final Project project, final Instant importedAt, final String specVersion) {
        final var bom = new Bom();
        bom.setProject(project);
        bom.setImported(Date.from(importedAt));
        bom.setBomFormat(Bom.Format.CYCLONEDX);
        bom.setSpecVersion(specVersion);
        bom.setBomVersion(1);
        return qm.persist(bom);
    }
}
