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
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.grizzly.connector.GrizzlyConnectorProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.spi.TestContainerException;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.support.AnnotationSupport;
import org.junitpioneer.jupiter.DefaultLocale;

import java.util.Locale;
import java.util.function.Supplier;

/**
 * @since 4.11.0
 */
public class JerseyTestExtension implements BeforeAllCallback, AfterAllCallback {

    private final Supplier<ResourceConfig> resourceConfigSupplier;
    private JerseyTest jerseyTest;

    public JerseyTestExtension(final Supplier<ResourceConfig> resourceConfigSupplier) {
        this.resourceConfigSupplier = resourceConfigSupplier;
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        final var testClass = context.getRequiredTestClass();
        final var defaultLocale = AnnotationSupport.findAnnotation(testClass, DefaultLocale.class);
        if (defaultLocale.isPresent()) {
            final var locale = Locale.forLanguageTag(defaultLocale.get().value());
            Locale.setDefault(locale);
        }

        this.jerseyTest = new JerseyTest() {
            @Override
            protected TestContainerFactory getTestContainerFactory() throws TestContainerException {
                return new DTGrizzlyWebTestContainerFactory();
            }

            @Override
            protected void configureClient(final ClientConfig config) {
                // Prevent InaccessibleObjectException with JDK >= 16 when performing PATCH requests
                // using the default HttpUrlConnection connector provider.
                // See https://github.com/eclipse-ee4j/jersey/issues/4825
                config.connectorProvider(new GrizzlyConnectorProvider());
            }

            @Override
            protected DeploymentContext configureDeployment() {
                return ServletDeploymentContext.forServlet(new ServletContainer(resourceConfigSupplier.get()
                        .packages("org.dependencytrack.resources.v1.exception"))).build();
            }
        };
        jerseyTest.setUp();
    }

    @Override
    public void afterAll(ExtensionContext context) {
        if (jerseyTest != null) {
            try {
                jerseyTest.tearDown();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                jerseyTest = null;
            }
        }
    }

    public WebTarget target() {
        return jerseyTest.target();
    }

    public final WebTarget target(final String path) {
        return jerseyTest.target(path);
    }

}
