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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.InputFormat;
import com.networknt.schema.JsonMetaSchema;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.NonValidationKeyword;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import com.networknt.schema.oas.OpenApi30;
import io.swagger.parser.OpenAPIParser;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.parser.ObjectMapperFactory;
import io.swagger.v3.parser.core.models.ParseOptions;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientResponseContext;
import jakarta.ws.rs.client.ClientResponseFilter;
import org.junit.jupiter.api.Assertions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * @since 5.0.0
 */
public class OpenApiValidationClientResponseFilter implements ClientResponseFilter {

    public static final String DISABLE_OPENAPI_VALIDATION = "disable-openapi-validation";

    private static final JsonSchemaFactory SCHEMA_FACTORY =
            JsonSchemaFactory.getInstance(
                    SpecVersion.VersionFlag.V4,
                    builder -> builder
                            .metaSchema(JsonMetaSchema.builder(OpenApi30.getInstance())
                                    .keyword(new NonValidationKeyword("exampleSetFlag"))
                                    .keyword(new NonValidationKeyword("extensions"))
                                    .keyword(new NonValidationKeyword("types"))
                                    .build())
                            .defaultMetaSchemaIri(OpenApi30.getInstance().getIri()));

    private final OpenAPI openApiSpec;
    private final ObjectMapper objectMapper;

    public OpenApiValidationClientResponseFilter() {
        this.openApiSpec = loadOpenApiSpec();
        this.objectMapper = ObjectMapperFactory.createJson();
    }

    @Override
    public void filter(
            final ClientRequestContext requestContext,
            final ClientResponseContext responseContext) throws IOException {
        if (requestContext.hasProperty(DISABLE_OPENAPI_VALIDATION)) {
            return;
        }

        final Operation operationDef = findOpenApiOperation(requestContext);
        if (operationDef == null) {
            // Undocumented request?
            Assertions.fail("No OpenAPI operation found for %s %s".formatted(
                    requestContext.getMethod(), requestContext.getUri()));
        }

        // Read the response content and assign it back to the response context.
        // Without this, clients won't be able to read the response any more.
        final String responseText = new String(responseContext.getEntityStream().readAllBytes());
        responseContext.setEntityStream(new ByteArrayInputStream(responseText.getBytes()));

        // Identity the correct response object in the spec based on the status.
        final String responseStatus = String.valueOf(responseContext.getStatus());
        assertThat(operationDef.getResponses().keySet())
                .as("""
                                Got response with status %s, but the OpenAPI spec of \
                                %s %s does not define it: %s""",
                        responseStatus,
                        requestContext.getMethod(),
                        requestContext.getUri(),
                        responseText)
                .contains(responseStatus);
        final ApiResponse responseDef = operationDef.getResponses().get(responseStatus);

        // If the spec does not define a response, ensure that the actual
        // response is also empty.
        if (responseDef.getContent() == null) {
            assertThat(responseText).asString()
                    .as("""
                                    Got response with content, but the OpenAPI spec of \
                                    %s %s -> %s does not define any: %s""",
                            requestContext.getMethod(),
                            requestContext.getUri(),
                            responseStatus,
                            responseText)
                    .isEmpty();
            return;
        }

        // Identity the correct media type in the spec response.
        final String responseContentType = responseContext.getHeaderString("Content-Type");
        assertThat(responseDef.getContent().keySet())
                .as("""
                                Got response with content-type %s, but the OpenAPI spec of \
                                %s %s -> %s does not define any responses for it: %s""",
                        responseContentType,
                        requestContext.getMethod(),
                        requestContext.getUri(),
                        responseStatus,
                        responseText)
                .contains(responseContentType);
        final MediaType mediaType = responseDef.getContent().get(responseContentType);

        // Serialize the response schema to JSON so it can be used for validation.
        // NB: The schema already has all $refs resolved so can be handled "standalone".
        final String schemaJson = objectMapper.writeValueAsString(mediaType.getSchema());
        final JsonSchema schema = SCHEMA_FACTORY.getSchema(schemaJson);

        final Set<ValidationMessage> messages = schema.validate(responseText, InputFormat.JSON);
        assertThat(messages)
                .as("""
                                Got response content that failed to validate against the \
                                OpenAPI spec of %s %s -> %s (%s): %s""",
                        requestContext.getMethod(),
                        requestContext.getUri(),
                        responseStatus,
                        responseContentType,
                        responseText)
                .isEmpty();
    }

    private Operation findOpenApiOperation(final ClientRequestContext requestContext) {
        final String requestPath = requestContext.getUri().getPath();

        for (final String specPath : openApiSpec.getPaths().keySet()) {
            if (!pathsMatch(requestPath, specPath)) {
                continue;
            }

            final PathItem pathItem = openApiSpec.getPaths().get(specPath);
            return switch (requestContext.getMethod()) {
                case "DELETE" -> pathItem.getDelete();
                case "GET" -> pathItem.getGet();
                case "HEAD" -> pathItem.getHead();
                case "OPTIONS" -> pathItem.getOptions();
                case "PATCH" -> pathItem.getPatch();
                case "POST" -> pathItem.getPost();
                case "PUT" -> pathItem.getPut();
                case "TRACE" -> pathItem.getTrace();
                default -> null;
            };
        }

        return null;
    }

    private boolean pathsMatch(final String requestPath, final String specPath) {
        final String[] requestPathSegments = requestPath.split("/");
        final String[] specPathSegments = specPath.split("/");

        if (requestPathSegments.length != specPathSegments.length) {
            return false;
        }

        for (int i = 0; i < requestPathSegments.length; i++) {
            final String requestPathSegment = requestPathSegments[i];
            final String specPathSegment = specPathSegments[i];

            if (!requestPathSegment.equals(specPathSegment) && !specPathSegment.startsWith("{")) {
                return false;
            }
        }

        return true;
    }

    private static OpenAPI loadOpenApiSpec() {
        try (final InputStream specInputStream =
                     OpenApiValidationClientResponseFilter.class.getResourceAsStream(
                             "/org/dependencytrack/api/v2/openapi.yaml")) {
            requireNonNull(specInputStream);
            final String specString = new String(specInputStream.readAllBytes());

            final var parseOptions = new ParseOptions();
            parseOptions.setResolve(true);
            parseOptions.setResolveFully(true);

            return new OpenAPIParser().readContents(specString, null, parseOptions).getOpenAPI();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load OpenAPI spec", e);
        }
    }

}
