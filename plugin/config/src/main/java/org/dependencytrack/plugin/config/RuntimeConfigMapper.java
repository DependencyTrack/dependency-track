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
package org.dependencytrack.plugin.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.networknt.schema.JsonMetaSchema;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.NonValidationKeyword;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import com.networknt.schema.serialization.DefaultJsonNodeReader;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * Mapper of {@link RuntimeConfig}s.
 * <p>
 * The mapper fulfills the following purposes:
 * <ul>
 *     <li>Serializes and deserializes {@link RuntimeConfig} instances to and from JSON</li>
 *     <li>Validates {@link RuntimeConfig} instances against their respective JSON schema</li>
 * </ul>
 * <p>
 * This class is thread-safe. To make effective use of the schema cache,
 * prefer using the global instance available via {@link #getInstance()},
 * instead of creating new instances ad-hoc.
 *
 * @since 5.0.0
 */
public final class RuntimeConfigMapper {

    private static class CustomAnnotations {
        private static final String I18N = "x-i18n";
        private static final String SECRET_REF = "x-secret-ref";
        private static final String UI_HINT = "x-ui-hint";
    }

    private static final RuntimeConfigMapper INSTANCE = new RuntimeConfigMapper();

    private final ObjectMapper jsonMapper;
    private final JsonSchemaFactory schemaFactory;
    private final Map<RuntimeConfigSpec, RuntimeConfigSchema> schemaCache;

    RuntimeConfigMapper() {
        this.jsonMapper = new ObjectMapper()
                .setDefaultPropertyInclusion(JsonInclude.Include.NON_EMPTY);
        final JsonMetaSchema jsonMetaSchema = JsonMetaSchema.builder(
                        JsonMetaSchema.getV202012().getIri(),
                        JsonMetaSchema.getV202012())
                // Don't emit warnings when encountering jsonschema2pojo extensions.
                // https://github.com/joelittlejohn/jsonschema2pojo/wiki/Reference#extensions
                .keywords(List.of(
                        new NonValidationKeyword("existingJavaType"),
                        new NonValidationKeyword("javaEnumNames"),
                        new NonValidationKeyword("javaEnums"),
                        new NonValidationKeyword("javaInterfaces"),
                        new NonValidationKeyword("javaJsonView"),
                        new NonValidationKeyword("javaName"),
                        new NonValidationKeyword("javaType")))
                // Don't emit warning when encountering custom annotations.
                .keywords(List.of(
                        new NonValidationKeyword(CustomAnnotations.I18N),
                        new NonValidationKeyword(CustomAnnotations.SECRET_REF),
                        new NonValidationKeyword(CustomAnnotations.UI_HINT)))
                .build();
        this.schemaFactory = JsonSchemaFactory
                .builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012))
                .jsonNodeReader(
                        DefaultJsonNodeReader.builder()
                                .jsonMapper(this.jsonMapper)
                                .build())
                .defaultMetaSchemaIri(jsonMetaSchema.getIri())
                .metaSchema(jsonMetaSchema)
                .build();
        this.schemaCache = new ConcurrentHashMap<>();
    }

    public static RuntimeConfigMapper getInstance() {
        return INSTANCE;
    }

    public <T extends RuntimeConfig> T convert(JsonNode configJsonNode, Class<T> configClass) {
        requireNonNull(configJsonNode, "configJsonNode must not be null");
        requireNonNull(configClass, "configClass must not be null");

        return jsonMapper.convertValue(configJsonNode, configClass);
    }

    /**
     * Serialize a given config to JSON.
     *
     * @param config The config to serialize.
     * @return The serialized config in JSON format.
     * @throws UncheckedIOException When serialization failed.
     * @throws NullPointerException When {@code config} is {@code null}.
     */
    public String serialize(RuntimeConfig config) {
        requireNonNull(config, "config must not be null");

        try {
            return jsonMapper.writeValueAsString(config);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Validate a given config against its JSON schema.
     *
     * @param config            The config to validate.
     * @param runtimeConfigSpec The applicable config spec.
     * @throws NullPointerException             When either {@code config} or {@code configSchemaJson} are {@code null}.
     * @throws UncheckedIOException             When parsing the config JSON failed.
     * @throws RuntimeConfigSchemaValidationException When the config failed validation.
     */
    public <T extends RuntimeConfig> JsonNode validate(T config, RuntimeConfigSpec runtimeConfigSpec) {
        requireNonNull(config, "config must not be null");
        requireNonNull(runtimeConfigSpec, "configSpec must not be null");

        final RuntimeConfigSchema schema = getSchema(runtimeConfigSpec);
        final JsonNode configNode = jsonMapper.convertValue(config, JsonNode.class);

        final Set<ValidationMessage> validationMessages = schema.jsonSchema().validate(configNode);
        if (!validationMessages.isEmpty()) {
            throw new RuntimeConfigSchemaValidationException(validationMessages);
        }

        if (runtimeConfigSpec.validator() != null) {
            runtimeConfigSpec.validator().validate(config);
        }

        return configNode;
    }

    /**
     * Validate a given config in JSON format against its schema.
     *
     * @param configJson        The config to validate in JSON format.
     * @param runtimeConfigSpec The applicable config spec.
     * @throws NullPointerException             When either {@code configJson} or {@code configSchemaJson} are {@code null}.
     * @throws UncheckedIOException             When parsing the config JSON failed.
     * @throws RuntimeConfigSchemaValidationException When the config failed validation.
     */
    public JsonNode validateJson(String configJson, RuntimeConfigSpec runtimeConfigSpec) {
        requireNonNull(configJson, "configJson must not be null");
        requireNonNull(runtimeConfigSpec, "configSpec must not be null");

        final RuntimeConfigSchema schema = getSchema(runtimeConfigSpec);

        final JsonNode configNode;
        try {
            configNode = jsonMapper.readValue(configJson, JsonNode.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        final Set<ValidationMessage> validationMessages = schema.jsonSchema().validate(configNode);
        if (!validationMessages.isEmpty()) {
            throw new RuntimeConfigSchemaValidationException(validationMessages);
        }

        return configNode;
    }

    /**
     * Resolve secret references in {@code configNode} to their corresponding secret values.
     *
     * @param configNode        The config JSON node to resolve secrets in.
     * @param runtimeConfigSpec The applicable config spec.
     * @param secretResolver    The secret resolver.
     * @throws UnresolvableSecretException When a secret could not be resolved.
     */
    public void resolveSecretRefs(
            JsonNode configNode,
            RuntimeConfigSpec runtimeConfigSpec,
            Function<String, @Nullable String> secretResolver) {
        final RuntimeConfigSchema schema = getSchema(runtimeConfigSpec);
        if (schema.secretRefPaths().isEmpty()) {
            return;
        }

        for (final String secretRefPath : schema.secretRefPaths()) {
            resolveSecretRefs(configNode, secretRefPath, secretResolver);
        }
    }

    public ObjectMapper getJsonMapper() {
        return jsonMapper;
    }

    private RuntimeConfigSchema getSchema(RuntimeConfigSpec runtimeConfigSpec) {
        return schemaCache.computeIfAbsent(
                runtimeConfigSpec,
                clazz -> {
                    final JsonNode schemaNode;
                    try {
                        schemaNode = jsonMapper.readValue(runtimeConfigSpec.schema(), JsonNode.class);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }

                    final JsonSchema jsonSchema = schemaFactory.getSchema(schemaNode);
                    if (jsonSchema.getId() == null || jsonSchema.getId().isBlank()) {
                        throw new IllegalStateException("Schema does not define an ID");
                    }

                    final Set<String> secretRefPaths = getSecretRefPaths(schemaNode, null);

                    return new RuntimeConfigSchema(jsonSchema, secretRefPaths);
                });
    }

    private Set<String> getSecretRefPaths(JsonNode schemaNode, @Nullable String currentPath) {
        if (!schemaNode.has("properties")) {
            return Collections.emptySet();
        }

        final JsonNode propertiesNode = schemaNode.get("properties");
        final Iterator<String> fieldNamesIterator = propertiesNode.fieldNames();

        final var paths = new HashSet<String>();

        while (fieldNamesIterator.hasNext()) {
            final String fieldName = fieldNamesIterator.next();
            final JsonNode propertySchemaNode = propertiesNode.get(fieldName);

            final String fieldPath = currentPath != null
                    ? currentPath + "/" + fieldName
                    : "/" + fieldName;

            if (hasSecretRef(propertySchemaNode, fieldPath)) {
                paths.add(fieldPath);
            }

            paths.addAll(getSecretRefPaths(propertySchemaNode, fieldPath));

            if (propertySchemaNode.has("items")) {
                final JsonNode itemsSchemaNode = propertySchemaNode.get("items");
                if (hasSecretRef(itemsSchemaNode, fieldPath)) {
                    paths.add(fieldPath + "[*]");
                }
                paths.addAll(getSecretRefPaths(itemsSchemaNode, fieldPath + "[*]"));
            }
        }

        return paths;
    }

    private boolean hasSecretRef(JsonNode propertyNode, String path) {
        if (!propertyNode.has(CustomAnnotations.SECRET_REF)) {
            return false;
        }

        final JsonNode secretRefNode = propertyNode.get(CustomAnnotations.SECRET_REF);
        if (!secretRefNode.isBoolean()) {
            throw new IllegalStateException(
                    "Invalid %s node type at %s: Expected %s but was %s".formatted(
                            CustomAnnotations.SECRET_REF, path, JsonNodeType.BOOLEAN, secretRefNode.getNodeType()));
        }

        return secretRefNode.asBoolean();
    }

    private void resolveSecretRefs(
            JsonNode configNode,
            String path,
            Function<String, @Nullable String> secretResolver) {
        // Handle array paths such as /foo[*]/bar manually because
        // JSON pointers don't support wildcards in array indexes.
        //
        // In the future we could possibly use a fully-fledged JSON path
        // implementation here, but for now this does the job.
        if (path.contains("[*]")) {
            // Deconstruct path: "/foo[*]/bar" -> "/foo", "/bar".
            final int arrayWildcardIndex = path.indexOf("[*]");
            final String pathBeforeWildcard = path.substring(0, arrayWildcardIndex);
            final String pathAfterWildcard = arrayWildcardIndex + 3 < path.length()
                    ? path.substring(arrayWildcardIndex + 3)
                    : null;

            if (!(configNode.at(pathBeforeWildcard) instanceof ArrayNode arrayNode)) {
                return;
            }

            for (int i = 0; i < arrayNode.size(); i++) {
                final JsonNode arrayItemNode = arrayNode.get(i);
                if (pathAfterWildcard != null) {
                    // Path refers to a nested node after the array, so recurse into that.
                    resolveSecretRefs(arrayItemNode, pathAfterWildcard, secretResolver);
                } else if (arrayItemNode.isTextual()) {
                    final String secretName = arrayItemNode.asText().trim();
                    if (!secretName.isEmpty()) {
                        final String secretValue = secretResolver.apply(secretName);
                        if (secretValue == null) {
                            throw new UnresolvableSecretException(secretName, pathBeforeWildcard + "[" + i + "]");
                        }
                        arrayNode.set(i, TextNode.valueOf(secretValue));
                    }
                }
            }
        } else {
            // Directly navigate to the secret ref node using JSON pointer.
            final JsonNode propertyNode = configNode.at(path);
            if (!propertyNode.isTextual()) {
                return;
            }

            final String secretName = propertyNode.asText().trim();
            if (secretName.isEmpty()) {
                return;
            }

            final String secretValue = secretResolver.apply(secretName);
            if (secretValue == null) {
                throw new UnresolvableSecretException(secretName, path);
            }

            // JSON values are immutable. To replace the secret ref
            // with the resolved secret, we need to replace the whole
            // node in its parent.
            final int lastSlash = path.lastIndexOf('/');
            if (lastSlash == 0) {
                // Path is at the root level (e.g. "/secretString").
                final String fieldName = path.substring(1);
                if (configNode instanceof final ObjectNode objectNode) {
                    objectNode.set(fieldName, TextNode.valueOf(secretValue));
                }
            } else {
                // Path is nested (e.g. "/nested/secretString").
                // Deconstruct: "/nested/secretString" -> "/nested", "secretString".
                final String parentPath = path.substring(0, lastSlash);
                final String fieldName = path.substring(lastSlash + 1);

                // Directly navigate to the parent node via JSON pointer.
                final JsonNode parentNode = configNode.at(parentPath);

                if (parentNode instanceof final ObjectNode objectNode) {
                    objectNode.set(fieldName, TextNode.valueOf(secretValue));
                } else {
                    throw new IllegalStateException(
                            "Unexpected node type at %s: Expected %s but was %s".formatted(
                                    path, JsonNodeType.OBJECT, parentNode.getNodeType()));
                }
            }
        }
    }

}
