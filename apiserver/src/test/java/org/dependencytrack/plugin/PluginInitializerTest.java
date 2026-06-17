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
package org.dependencytrack.plugin;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.notification.publishing.DefaultNotificationPublishersPlugin;
import org.dependencytrack.pkgmetadata.resolution.DefaultPackageMetadataResolutionPlugin;
import org.dependencytrack.plugin.runtime.ExtensionPointMetadata;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.secret.TestSecretManager;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.vulnanalysis.internal.InternalVulnAnalyzerPlugin;
import org.dependencytrack.vulnanalysis.ossindex.OssIndexVulnAnalyzerPlugin;
import org.dependencytrack.vulnanalysis.snyk.SnykVulnAnalyzerPlugin;
import org.dependencytrack.vulnanalysis.trivy.TrivyVulnAnalyzerPlugin;
import org.dependencytrack.vulnanalysis.vulndb.VulnDbVulnAnalyzerPlugin;
import org.dependencytrack.vulndatasource.github.GitHubVulnDataSourcePlugin;
import org.dependencytrack.vulndatasource.nvd.NvdVulnDataSourcePlugin;
import org.dependencytrack.vulndatasource.osv.OsvVulnDataSourcePlugin;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class PluginInitializerTest extends PersistenceCapableTest {

    private final List<Runnable> cleanupTasks = new ArrayList<>();

    @AfterEach
    void afterEach() {
        cleanupTasks.forEach(Runnable::run);
    }

    @Test
    void shouldLoadAndUnloadPlugins() {
        // Test against "production" config for more realistic test coverage.
        final Config config = ConfigProvider.getConfig();

        final var servletContextMock = mock(ServletContext.class);
        doReturn(new NoopCacheManager())
                .when(servletContextMock).getAttribute(eq(CacheManager.class.getName()));
        doReturn(new TestSecretManager())
                .when(servletContextMock).getAttribute(eq(SecretManager.class.getName()));

        final var attributeValueCaptor = ArgumentCaptor.forClass(PluginManager.class);

        final var initializer = new PluginInitializer(config);
        initializer.contextInitialized(new ServletContextEvent(servletContextMock));

        verify(servletContextMock).setAttribute(
                eq(PluginManager.class.getName()),
                attributeValueCaptor.capture());

        final PluginManager pluginManager = attributeValueCaptor.getValue();
        assertThat(pluginManager).isNotNull();
        assertThat(pluginManager.isClosed()).isFalse();

        // Make sure resources are released even when the following assertions fail.
        cleanupTasks.add(pluginManager::close);

        assertThat(pluginManager.getExtensionPoints())
                .extracting(ExtensionPointMetadata::name)
                .containsExactlyInAnyOrder(
                        "notification-publisher",
                        "package-metadata-resolver",
                        "vuln-analyzer",
                        "vuln-data-source");
        assertThat(pluginManager.getLoadedPlugins()).satisfiesExactlyInAnyOrder(
                plugin -> assertThat(plugin).isInstanceOf(DefaultNotificationPublishersPlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(DefaultPackageMetadataResolutionPlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(GitHubVulnDataSourcePlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(InternalVulnAnalyzerPlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(NvdVulnDataSourcePlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(OssIndexVulnAnalyzerPlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(OsvVulnDataSourcePlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(SnykVulnAnalyzerPlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(TrivyVulnAnalyzerPlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(VulnDbVulnAnalyzerPlugin.class));

        initializer.contextDestroyed(new ServletContextEvent(servletContextMock));

        assertThat(pluginManager.isClosed()).isTrue();

        verify(servletContextMock).removeAttribute(eq(PluginManager.class.getName()));
    }

}