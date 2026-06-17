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
package org.dependencytrack;

import jakarta.ws.rs.client.WebTarget;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.dependencytrack.resources.v2.OpenApiValidationClientResponseFilter;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.spi.TestContainerException;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * @since 5.0.0
 */
public class JerseyTestExtension implements BeforeAllCallback, AfterAllCallback, BeforeEachCallback, AfterEachCallback {

    private final JerseyTest jerseyTest;
    private boolean isSetUp = false;

    public JerseyTestExtension(final ResourceConfig resourceConfig) {
        final boolean isV2 = isV2(resourceConfig);
        this.jerseyTest = new JerseyTest() {

            @Override
            protected TestContainerFactory getTestContainerFactory() throws TestContainerException {
                return new DTGrizzlyWebTestContainerFactory();
            }

            @Override
            protected void configureClient(final ClientConfig config) {
                config.connectorProvider(
                        new HttpUrlConnectorProvider()
                                // Required for PATCH support.
                                // See https://github.com/eclipse-ee4j/jersey/issues/4825
                                .useSetMethodWorkaround());

                if (isV2) {
                    config.register(OpenApiValidationClientResponseFilter.class);
                    // Ensure multipart support is available on the client for v2 multipart endpoints
                    config.register(MultiPartFeature.class);
                }
            }

            @Override
            protected DeploymentContext configureDeployment() {
                forceSet(TestProperties.CONTAINER_PORT, "0");

                // Ensure exception mappers are registered.
                if (isV2) {
                    resourceConfig.packages("org.dependencytrack.resources.v2.exception");
                } else {
                    resourceConfig.packages("org.dependencytrack.resources.v1.exception");
                }

                return ServletDeploymentContext.forServlet(
                        new ServletContainer(resourceConfig)).build();
            }

        };
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        jerseyTest.setUp();
        isSetUp = true;
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        if (isSetUp) {
            jerseyTest.tearDown();
            isSetUp = false;
        }
    }

    @Override
    public void beforeEach(ExtensionContext context) {
    }

    @Override
    public void afterEach(ExtensionContext context) {
    }

    public WebTarget target() {
        return jerseyTest.target();
    }

    public final WebTarget target(final String path) {
        return jerseyTest.target(path);
    }

    public final WebTarget target(final URI uri) {
        WebTarget target = jerseyTest.target(uri.getPath());

        if (uri.getQuery() != null) {
            final List<NameValuePair> uriQueryParams =
                    URLEncodedUtils.parse(uri, StandardCharsets.UTF_8);
            for (final NameValuePair queryParam : uriQueryParams) {
                target = target.queryParam(queryParam.getName(), queryParam.getValue());
            }
        }

        return target;
    }

    private boolean isV2(final ResourceConfig resourceConfig) {
        for (final Class<?> clazz : resourceConfig.getClasses()) {
            if (clazz.getPackageName().startsWith("org.dependencytrack.resources.v2")) {
                return true;
            }
        }

        return false;
    }

}
