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
package org.dependencytrack.resources.v1;

import alpine.server.auth.AuthenticationNotRequired;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.util.Objects.requireNonNull;

/**
 * @since 4.12.0
 */
@Path("/openapi.{type:json|yaml}")
public class OpenApiResource {

    private static final ReadWriteLock LOCK = new ReentrantReadWriteLock();
    private static String OPENAPI_JSON;
    private static String OPENAPI_YAML;

    @GET
    @Produces({MediaType.APPLICATION_JSON, "application/yaml"})
    @Operation(hidden = true)
    @AuthenticationNotRequired
    public Response getOpenApi(@PathParam("type") final String type) throws IOException {
        return switch (type) {
            case "json" -> Response.ok(getJson(), MediaType.APPLICATION_JSON).build();
            case "yaml" -> Response.ok(getYaml(), "application/yaml").build();
            default -> Response.status(Response.Status.NOT_FOUND).build();
        };
    }

    private String getYaml() throws IOException {
        LOCK.readLock().lock();
        try {
            if (OPENAPI_YAML != null) {
                return OPENAPI_YAML;
            }
        } finally {
            LOCK.readLock().unlock();
        }

        LOCK.writeLock().lock();
        try {
            if (OPENAPI_YAML == null) {
                OPENAPI_YAML = loadYamlFromClasspath();
            }
            return OPENAPI_YAML;
        } finally {
            LOCK.writeLock().unlock();
        }
    }

    private String getJson() throws IOException {
        LOCK.readLock().lock();
        try {
            if (OPENAPI_JSON != null) {
                return OPENAPI_JSON;
            }
        } finally {
            LOCK.readLock().unlock();
        }

        LOCK.writeLock().lock();
        try {
            if (OPENAPI_JSON == null) {
                final var yamlMapper = new ObjectMapper(new YAMLFactory());
                final var jsonMapper = new ObjectMapper();

                final JsonNode spec = yamlMapper.readTree(getYaml());
                OPENAPI_JSON = jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(spec);
            }
            return OPENAPI_JSON;
        } finally {
            LOCK.writeLock().unlock();
        }
    }

    private static String loadYamlFromClasspath() throws IOException {
        try (final InputStream inputStream = OpenApiResource.class
                .getResourceAsStream("/org/dependencytrack/api/v1/openapi.yaml")) {
            requireNonNull(inputStream, "OpenAPI spec not found on classpath");
            return new String(inputStream.readAllBytes());
        }
    }

}
