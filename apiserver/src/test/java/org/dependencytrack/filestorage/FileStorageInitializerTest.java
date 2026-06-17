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
package org.dependencytrack.filestorage;

import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.dependencytrack.filestorage.api.FileStorage;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class FileStorageInitializerTest {

    @Test
    void shouldInitializeMemoryProvider() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.of("dt.file-storage.provider", "memory"))
                .build();

        final var servletContextMock = mock(ServletContext.class);
        final var attributeValueCaptor = ArgumentCaptor.forClass(FileStorage.class);

        final var initializer = new FileStorageInitializer(config);
        initializer.contextInitialized(new ServletContextEvent(servletContextMock));

        verify(servletContextMock).setAttribute(
                eq(FileStorage.class.getName()),
                attributeValueCaptor.capture());

        final FileStorage fileStorage = attributeValueCaptor.getValue();
        assertThat(fileStorage).isNotNull();
        assertThat(fileStorage.name()).isEqualTo("memory");

        initializer.contextDestroyed(new ServletContextEvent(servletContextMock));
    }

    @Test
    void shouldThrowWhenProviderNotFound() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.of("dt.file-storage.provider", "nonexistent"))
                .build();

        final var servletContextMock = mock(ServletContext.class);

        final var initializer = new FileStorageInitializer(config);
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> initializer.contextInitialized(new ServletContextEvent(servletContextMock)))
                .withMessage("No file storage provider found for name: nonexistent");
    }

}
