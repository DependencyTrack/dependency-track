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
package org.dependencytrack.secret;

import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.dependencytrack.secret.management.SecretManager;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class SecretManagerInitializerTest {

    @AfterEach
    public void afterEach() {
        if (SecretManagerInitializer.secretManager != null) {
            SecretManagerInitializer.secretManager.close();
            SecretManagerInitializer.secretManager = null;
        }
    }

    @Test
    public void shouldInitializeSecretManager() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.secret-management.provider", "test")
                .build();

        final var servletContextMock = mock(ServletContext.class);

        new SecretManagerInitializer(config).contextInitialized(
                new ServletContextEvent(servletContextMock));

        final var secretManagerCaptor = ArgumentCaptor.forClass(SecretManager.class);
        verify(servletContextMock).setAttribute(
                eq(SecretManager.class.getName()),
                secretManagerCaptor.capture());
        assertThat(SecretManagerInitializer.secretManager).isEqualTo(secretManagerCaptor.getValue());

        assertThat(secretManagerCaptor.getValue()).isInstanceOf(TestSecretManager.class);
        assertThat(secretManagerCaptor.getValue().name()).isEqualTo("test");
    }

    @Test
    public void shouldThrowForUnknownType() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.secret-management.provider", "unknown")
                .build();

        final var servletContextMock = mock(ServletContext.class);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> new SecretManagerInitializer(config)
                        .contextInitialized(new ServletContextEvent(servletContextMock)))
                .withMessage("No secret management provider found for name: unknown");

        verify(servletContextMock, never()).setAttribute(eq(SecretManager.class.getName()), any());
    }

    @Test
    public void shouldClose() {
        final var secretManagerMock = mock(SecretManager.class);
        SecretManagerInitializer.secretManager = secretManagerMock;

        new SecretManagerInitializer(new SmallRyeConfigBuilder().build())
                .contextDestroyed(new ServletContextEvent(mock(ServletContext.class)));

        verify(secretManagerMock).close();
    }

}