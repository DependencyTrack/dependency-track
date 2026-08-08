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
package org.dependencytrack.filestorage.s3;

import io.minio.credentials.ChainedProvider;
import io.minio.credentials.StaticProvider;
import io.smallrye.config.SmallRyeConfigBuilder;
import okhttp3.OkHttpClient;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class S3FileStorageProviderTest {

    @Test
    void shouldHaveNameS3() {
        final var provider = new S3FileStorageProvider();
        assertThat(provider.name()).isEqualTo("s3");
    }

    @Test
    void resolveCredentialsProviderShouldReturnStaticProviderByDefault() {
        final Config config = configOf(Map.ofEntries(
                Map.entry("dt.file-storage.s3.access-key", "foo"),
                Map.entry("dt.file-storage.s3.secret-key", "bar")));

        assertThat(S3FileStorageProvider.resolveCredentialsProvider(config, new OkHttpClient()))
                .hasValueSatisfying(provider -> assertThat(provider).isInstanceOf(StaticProvider.class));
    }

    @Test
    void resolveCredentialsProviderShouldReturnStaticProviderWhenSourceIsStatic() {
        final Config config = configOf(Map.ofEntries(
                Map.entry("dt.file-storage.s3.credentials-source", "static"),
                Map.entry("dt.file-storage.s3.access-key", "foo"),
                Map.entry("dt.file-storage.s3.secret-key", "bar")));

        assertThat(S3FileStorageProvider.resolveCredentialsProvider(config, new OkHttpClient()))
                .hasValueSatisfying(provider -> assertThat(provider).isInstanceOf(StaticProvider.class));
    }

    @Test
    void resolveCredentialsProviderShouldReturnEmptyWhenStaticKeysAreMissing() {
        final Config config = configOf(Map.ofEntries(
                Map.entry("dt.file-storage.s3.credentials-source", "static")));

        assertThat(S3FileStorageProvider.resolveCredentialsProvider(config, new OkHttpClient())).isEmpty();
    }

    @Test
    void resolveCredentialsProviderShouldThrowWhenOnlyAccessKeyIsConfigured() {
        final Config config = configOf(Map.ofEntries(
                Map.entry("dt.file-storage.s3.credentials-source", "static"),
                Map.entry("dt.file-storage.s3.access-key", "foo")));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> S3FileStorageProvider.resolveCredentialsProvider(config, new OkHttpClient()))
                .withMessage("Both dt.file-storage.s3.access-key and dt.file-storage.s3.secret-key "
                        + "must be set when using static credentials");
    }

    @Test
    void resolveCredentialsProviderShouldThrowWhenOnlySecretKeyIsConfigured() {
        final Config config = configOf(Map.ofEntries(
                Map.entry("dt.file-storage.s3.credentials-source", "static"),
                Map.entry("dt.file-storage.s3.secret-key", "bar")));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> S3FileStorageProvider.resolveCredentialsProvider(config, new OkHttpClient()))
                .withMessage("Both dt.file-storage.s3.access-key and dt.file-storage.s3.secret-key "
                        + "must be set when using static credentials");
    }

    @Test
    void resolveCredentialsProviderShouldReturnChainedProviderWhenSourceIsAws() {
        final Config config = configOf(Map.ofEntries(
                Map.entry("dt.file-storage.s3.credentials-source", "aws")));

        assertThat(S3FileStorageProvider.resolveCredentialsProvider(config, new OkHttpClient()))
                .hasValueSatisfying(provider -> assertThat(provider).isInstanceOf(ChainedProvider.class));
    }

    @Test
    void resolveCredentialsProviderShouldThrowWhenAwsSourceIsCombinedWithStaticCredentials() {
        final Config config = configOf(Map.ofEntries(
                Map.entry("dt.file-storage.s3.credentials-source", "aws"),
                Map.entry("dt.file-storage.s3.access-key", "foo"),
                Map.entry("dt.file-storage.s3.secret-key", "bar")));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> S3FileStorageProvider.resolveCredentialsProvider(config, new OkHttpClient()))
                .withMessageContaining("Conflicting credentials configuration");
    }

    /**
     * {@link io.minio.credentials.EnvironmentProvider} reads system properties before environment
     * variables, which is what allows this test to drive the chain without a real AWS environment.
     */
    @Test
    void resolveCredentialsProviderShouldConsultAwsEnvironmentWhenSourceIsAws() {
        final Config config = configOf(Map.ofEntries(
                Map.entry("dt.file-storage.s3.credentials-source", "aws")));

        System.setProperty("AWS_ACCESS_KEY_ID", "foo");
        System.setProperty("AWS_SECRET_ACCESS_KEY", "bar");
        try {
            assertThat(S3FileStorageProvider.resolveCredentialsProvider(config, new OkHttpClient()))
                    .hasValueSatisfying(provider -> assertThat(provider.fetch())
                            .satisfies(credentials -> {
                                assertThat(credentials.accessKey()).isEqualTo("foo");
                                assertThat(credentials.secretKey()).isEqualTo("bar");
                            }));
        } finally {
            System.clearProperty("AWS_ACCESS_KEY_ID");
            System.clearProperty("AWS_SECRET_ACCESS_KEY");
        }
    }

    @Test
    void resolveCredentialsProviderShouldThrowWhenSourceIsInvalid() {
        final Config config = configOf(Map.ofEntries(
                Map.entry("dt.file-storage.s3.credentials-source", "bogus")));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> S3FileStorageProvider.resolveCredentialsProvider(config, new OkHttpClient()));
    }

    private static Config configOf(Map<String, String> configValues) {
        return new SmallRyeConfigBuilder()
                .withDefaultValues(configValues)
                .build();
    }

}
