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

import org.apache.commons.lang3.reflect.FieldUtils;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainer;
import org.glassfish.jersey.test.spi.TestContainerFactory;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Custom factory needed to instantiate a TestContainer allowing body payload for DELETE method.
 */
public class DTGrizzlyWebTestContainerFactory implements TestContainerFactory {
    @Override
    public TestContainer create(URI baseUri, DeploymentContext deploymentContext) {
        if (!(deploymentContext instanceof ServletDeploymentContext)) {
            throw new IllegalArgumentException("The deployment context must be an instance of ServletDeploymentContext.");
        }

        final TestContainer testContainer = new GrizzlyWebTestContainerFactory().create(baseUri, deploymentContext);
        try {
            HttpServer server = (HttpServer) FieldUtils.readDeclaredField(testContainer, "server", true);
            server.getServerConfiguration().setAllowPayloadForUndefinedHttpMethods(true);
        } catch (IllegalAccessException e) {
            fail(e.getMessage());
        }
        return testContainer;
    }
}
