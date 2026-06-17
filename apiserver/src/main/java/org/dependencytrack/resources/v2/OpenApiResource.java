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

import alpine.server.auth.AuthenticationNotRequired;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import org.dependencytrack.resources.AbstractApiResource;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.util.Objects.requireNonNull;

@Path("/openapi.yaml")
public class OpenApiResource extends AbstractApiResource {

    private static final ReadWriteLock LOCK = new ReentrantReadWriteLock();
    private static String OPENAPI_YAML;

    @GET
    @Produces("application/yaml")
    @Operation(hidden = true)
    @AuthenticationNotRequired
    public String getOpenApi() throws IOException {
        LOCK.readLock().lock();
        try {
            if (OPENAPI_YAML == null) {
                LOCK.readLock().unlock();

                LOCK.writeLock().lock();
                try {
                    if (OPENAPI_YAML == null) {
                        OPENAPI_YAML = loadOpenapiYaml();
                    }

                    LOCK.readLock().lock();
                } finally {
                    LOCK.writeLock().unlock();
                }
            }

            return OPENAPI_YAML;
        } finally {
            LOCK.readLock().unlock();
        }
    }

    private static String loadOpenapiYaml() throws IOException {
        try (final InputStream inputStream =
                     OpenApiResource.class.getResourceAsStream(
                             "/org/dependencytrack/api/v2/openapi.yaml")) {
            requireNonNull(inputStream, "inputStream must not be null");
            return new String(inputStream.readAllBytes());
        }
    }

}
