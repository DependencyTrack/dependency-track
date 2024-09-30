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

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.grizzly.connector.GrizzlyConnectorProvider;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.spi.TestContainerException;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.rules.ExternalResource;

import jakarta.ws.rs.client.WebTarget;

/**
 * @since 4.11.0
 */
public class JerseyTestRule extends ExternalResource {

    private final JerseyTest jerseyTest;

    public JerseyTestRule(final ResourceConfig resourceConfig) {
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
                return ServletDeploymentContext.forServlet(new ServletContainer(resourceConfig)).build();
            }

        };
    }

    @Override
    protected void before() throws Throwable {
        jerseyTest.setUp();
    }

    @Override
    protected void after() {
        try {
            jerseyTest.tearDown();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public WebTarget target() {
        return jerseyTest.target();
    }

    public final WebTarget target(final String path) {
        return jerseyTest.target(path);
    }

}
