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
package org.dependencytrack.secret.management.env;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.SimplePageTokenEncoder;
import org.dependencytrack.secret.management.ListSecretsRequest;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class EnvSecretManagerTest {

    private SecretManager secretManager;

    @BeforeEach
    void beforeEach() {
        secretManager = new EnvSecretManagerProvider(
                Map.of("dt_secret_name", "value"))
                .create(null, new SimplePageTokenEncoder());
    }

    @AfterEach
    void afterEach() {
        if (secretManager != null) {
            secretManager.close();
        }
    }

    @Test
    void nameShouldBeEnv() {
        assertThat(secretManager.name()).isEqualTo("env");
    }

    @Test
    void isReadOnlyShouldReturnTrue() {
        assertThat(secretManager.isReadOnly()).isTrue();
    }

    @Test
    void createSecretShouldThrow() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> secretManager.createSecret("foo", null, "bar"));
    }

    @Test
    void updateSecretShouldThrow() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> secretManager.updateSecret("name", null, "foo"));
    }

    @Test
    void deleteSecretShouldThrow() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> secretManager.deleteSecret("name"));
    }

    @Test
    void getSecretValueShouldReturnValue() {
        assertThat(secretManager.getSecretValue("name")).isEqualTo("value");
    }

    @Test
    void getSecretValueShouldReturnNullWhenNotFound() {
        assertThat(secretManager.getSecretValue("doesNotExist")).isNull();
    }

    @Test
    void getSecretMetadataShouldReturnMetadataIfExists() {
        final var metadata = secretManager.getSecretMetadata("name");
        assertThat(metadata).isNotNull();
        assertThat(metadata.name()).isEqualTo("name");
        assertThat(metadata.description()).isNull();
        assertThat(metadata.createdAt()).isNull();
        assertThat(metadata.updatedAt()).isNull();
    }

    @Test
    void getSecretMetadataShouldReturnNullWhenNotFound() {
        assertThat(secretManager.getSecretMetadata("doesNotExist")).isNull();
    }

    @Test
    void listSecretMetadataShouldReturnSecretMetadata() {
        final Page<SecretMetadata> page = secretManager.listSecretMetadata(
                new ListSecretsRequest(null, null, 100));

        assertThat(page.nextPageToken()).isNull();
        assertThat(page.totalCount()).isNotNull();
        assertThat(page.totalCount().value()).isEqualTo(1);
        assertThat(page.totalCount().type()).isEqualTo(Page.TotalCount.Type.EXACT);
        assertThat(page.items()).satisfiesExactly(secretMetadata -> {
            assertThat(secretMetadata.name()).isEqualTo("name");
            assertThat(secretMetadata.description()).isNull();
            assertThat(secretMetadata.createdAt()).isNull();
            assertThat(secretMetadata.updatedAt()).isNull();
        });
    }

    @Test
    void listSecretMetadataShouldSupportPagination() {
        secretManager = new EnvSecretManagerProvider(
                Map.of(
                        "dt_secret_alpha", "v1",
                        "dt_secret_beta", "v2",
                        "dt_secret_gamma", "v3"))
                .create(null, new SimplePageTokenEncoder());

        final Page<SecretMetadata> firstPage = secretManager.listSecretMetadata(
                new ListSecretsRequest(null, null, 2));

        assertThat(firstPage.items()).extracting(SecretMetadata::name)
                .containsExactly("alpha", "beta");
        assertThat(firstPage.nextPageToken()).isNotNull();
        assertThat(firstPage.totalCount().value()).isEqualTo(3);

        final Page<SecretMetadata> secondPage = secretManager.listSecretMetadata(
                new ListSecretsRequest(null, firstPage.nextPageToken(), 2));

        assertThat(secondPage.items()).extracting(SecretMetadata::name)
                .containsExactly("gamma");
        assertThat(secondPage.nextPageToken()).isNull();
        assertThat(secondPage.totalCount().value()).isEqualTo(3);
    }

    @Test
    void listSecretMetadataShouldSupportSearchText() {
        secretManager = new EnvSecretManagerProvider(
                Map.of(
                        "dt_secret_alpha", "v1",
                        "dt_secret_beta", "v2",
                        "dt_secret_ALPHABET", "v3"))
                .create(null, new SimplePageTokenEncoder());

        final Page<SecretMetadata> page = secretManager.listSecretMetadata(
                new ListSecretsRequest("alph", null, 100));

        assertThat(page.items()).extracting(SecretMetadata::name)
                .containsExactly("ALPHABET", "alpha");
        assertThat(page.nextPageToken()).isNull();
        assertThat(page.totalCount().value()).isEqualTo(2);
    }

    @Test
    void listSecretMetadataShouldSupportSearchTextWithPagination() {
        secretManager = new EnvSecretManagerProvider(
                Map.of(
                        "dt_secret_foo1", "v1",
                        "dt_secret_foo2", "v2",
                        "dt_secret_foo3", "v3",
                        "dt_secret_bar1", "v4"))
                .create(null, new SimplePageTokenEncoder());

        final Page<SecretMetadata> firstPage = secretManager.listSecretMetadata(
                new ListSecretsRequest("foo", null, 2));

        assertThat(firstPage.items()).extracting(SecretMetadata::name)
                .containsExactly("foo1", "foo2");
        assertThat(firstPage.nextPageToken()).isNotNull();
        assertThat(firstPage.totalCount().value()).isEqualTo(3);

        final Page<SecretMetadata> secondPage = secretManager.listSecretMetadata(
                new ListSecretsRequest("foo", firstPage.nextPageToken(), 2));

        assertThat(secondPage.items()).extracting(SecretMetadata::name)
                .containsExactly("foo3");
        assertThat(secondPage.nextPageToken()).isNull();
        assertThat(secondPage.totalCount().value()).isEqualTo(3);
    }

}
