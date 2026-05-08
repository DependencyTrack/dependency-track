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

import alpine.server.auth.PermissionRequired;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.ExtensionsApi;
import org.dependencytrack.api.v2.model.GetExtensionConfigResponse;
import org.dependencytrack.api.v2.model.ListExtensionPointsResponse;
import org.dependencytrack.api.v2.model.ListExtensionPointsResponseItem;
import org.dependencytrack.api.v2.model.ListExtensionsResponse;
import org.dependencytrack.api.v2.model.ListExtensionsResponseItem;
import org.dependencytrack.api.v2.model.TestExtensionRequest;
import org.dependencytrack.api.v2.model.TestExtensionResponse;
import org.dependencytrack.api.v2.model.TotalCount;
import org.dependencytrack.api.v2.model.TotalCountType;
import org.dependencytrack.api.v2.model.UpdateExtensionConfigRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.MdcScope;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionTestCheck;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.Testable;
import org.dependencytrack.plugin.api.config.MutableConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.dependencytrack.plugin.config.UnresolvableSecretException;
import org.dependencytrack.plugin.runtime.ExtensionPointMetadata;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.secret.management.SecretManager;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Comparator;
import java.util.Map;
import java.util.SequencedCollection;

import static org.dependencytrack.common.MdcKeys.MDC_EXTENSION_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_EXTENSION_POINT_NAME;

/**
 * @since 5.0.0
 */
@Provider
public class ExtensionsResource extends AbstractApiResource implements ExtensionsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExtensionsResource.class);

    private final PluginManager pluginManager;
    private final SecretManager secretManager;
    private final RuntimeConfigMapper configMapper;

    @Inject
    ExtensionsResource(PluginManager pluginManager, SecretManager secretManager) {
        this.pluginManager = pluginManager;
        this.secretManager = secretManager;
        this.configMapper = RuntimeConfigMapper.getInstance();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listExtensionPoints() {
        final SequencedCollection<ExtensionPointMetadata> extensionPoints =
                pluginManager.getExtensionPoints();

        final var response = ListExtensionPointsResponse.builder()
                .items(
                        extensionPoints.stream()
                                .map(ExtensionPointMetadata::name)
                                .sorted()
                                .<ListExtensionPointsResponseItem>map(
                                        name -> ListExtensionPointsResponseItem.builder()
                                                .name(name)
                                                .build())
                                .toList())
                .total(
                        TotalCount.builder()
                                .count((long) extensionPoints.size())
                                .type(TotalCountType.EXACT)
                                .build())
                .build();

        return Response.ok(response).build();
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listExtensions(String extensionPointName) {
        final Class<? extends ExtensionPoint> extensionPointClass =
                getExtensionPointClass(extensionPointName);

        final SequencedCollection<ExtensionFactory> extensionFactories =
                pluginManager.getFactories(extensionPointClass);

        final var response = ListExtensionsResponse.builder()
                .items(
                        extensionFactories.stream()
                                .sorted(Comparator.comparing(ExtensionFactory::extensionName))
                                .<ListExtensionsResponseItem>map(
                                        extensionFactory -> ListExtensionsResponseItem.builder()
                                                .name(extensionFactory.extensionName())
                                                .configurable(extensionFactory instanceof RuntimeConfigurable)
                                                .testable(extensionFactory instanceof Testable)
                                                .build())
                                .toList())
                .total(
                        TotalCount.builder()
                                .count((long) extensionFactories.size())
                                .type(TotalCountType.EXACT)
                                .build())
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getExtensionConfig(
            String extensionPointName,
            String extensionName) {
        final Class<? extends ExtensionPoint> extensionPointClass =
                getExtensionPointClass(extensionPointName);
        final ExtensionFactory<?> extensionFactory =
                getExtensionFactory(extensionPointClass, extensionName);

        if (!(extensionFactory instanceof RuntimeConfigurable rc)
                || rc.runtimeConfigSpec() == null) {
            throw new NotFoundException();
        }

        final MutableConfigRegistry configRegistry =
                pluginManager.getMutableConfigRegistry(extensionPointClass, extensionName);
        final String configJson = configRegistry.getRawRuntimeConfig().orElse(null);
        if (configJson == null) {
            throw new NotFoundException();
        }

        final ObjectMapper jsonMapper = RuntimeConfigMapper.getInstance().getJsonMapper();
        final Map<String, Object> parsedConfigJson;
        try {
            parsedConfigJson = jsonMapper.readValue(configJson, new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        final var response = GetExtensionConfigResponse.builder()
                .config(parsedConfigJson)
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateExtensionConfig(
            String extensionPointName,
            String extensionName,
            UpdateExtensionConfigRequest request) {
        final Class<? extends ExtensionPoint> extensionPointClass =
                getExtensionPointClass(extensionPointName);
        final ExtensionFactory<?> extensionFactory =
                getExtensionFactory(extensionPointClass, extensionName);

        final RuntimeConfigSpec runtimeConfigSpec =
                extensionFactory instanceof RuntimeConfigurable rc
                        ? rc.runtimeConfigSpec()
                        : null;
        if (runtimeConfigSpec == null) {
            throw new BadRequestException();
        }

        // Unfortunately we can't receive the config object as raw string,
        // so we have to serialize it first.
        final String configJson = Json.createObjectBuilder(request.getConfig()).build().toString();

        // Throws when config is invalid or secrets cannot be resolved.
        final JsonNode configNode = validateConfigAndResolveSecrets(configJson, runtimeConfigSpec);

        final RuntimeConfig config = configMapper.convert(configNode, runtimeConfigSpec.configClass());
        if (runtimeConfigSpec.validator() != null) {
            runtimeConfigSpec.validator().validate(config);
        }

        final MutableConfigRegistry configRegistry =
                pluginManager.getMutableConfigRegistry(extensionPointClass, extensionName);
        final boolean updated = configRegistry.setRawRuntimeConfig(configJson);
        if (!updated) {
            return Response.notModified().build();
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Updated config of extension {}/{}",
                extensionPointName,
                extensionName);

        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getExtensionConfigSchema(
            String extensionPointName,
            String extensionName) {
        final Class<? extends ExtensionPoint> extensionPointClass =
                getExtensionPointClass(extensionPointName);
        final ExtensionFactory<?> extensionFactory =
                getExtensionFactory(extensionPointClass, extensionName);

        final RuntimeConfigSpec runtimeConfigSpec =
                extensionFactory instanceof RuntimeConfigurable rc
                        ? rc.runtimeConfigSpec()
                        : null;
        if (runtimeConfigSpec == null) {
            return Response.noContent().build();
        }

        return Response.ok(runtimeConfigSpec.schema()).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response testExtension(
            String extensionPointName,
            String extensionName,
            TestExtensionRequest request) {
        final Class<? extends ExtensionPoint> extensionPointClass =
                getExtensionPointClass(extensionPointName);
        final ExtensionFactory<?> extensionFactory =
                getExtensionFactory(extensionPointClass, extensionName);

        try (var ignoredMdcScope = new MdcScope(Map.ofEntries(
                Map.entry(MDC_EXTENSION_POINT_NAME, extensionPointName),
                Map.entry(MDC_EXTENSION_NAME, extensionName)))) {
            LOGGER.info(
                    SecurityMarkers.SECURITY_AUDIT,
                    "Extension test requested with configuration: {}",
                    request.getConfig());
        }

        RuntimeConfig runtimeConfig = null;
        final RuntimeConfigSpec runtimeConfigSpec =
                extensionFactory instanceof RuntimeConfigurable rc
                        ? rc.runtimeConfigSpec()
                        : null;
        if (runtimeConfigSpec == null) {
            if (request.getConfig() != null) {
                throw new BadRequestException("The extension does not support configuration");
            }
        } else {
            final String configJson = Json.createObjectBuilder(request.getConfig()).build().toString();
            final JsonNode configNode = validateConfigAndResolveSecrets(configJson, runtimeConfigSpec);
            runtimeConfig = configMapper.convert(configNode, runtimeConfigSpec.configClass());
            if (runtimeConfigSpec.validator() != null) {
                runtimeConfigSpec.validator().validate(runtimeConfig);
            }
        }

        if (!(extensionFactory instanceof Testable testable)) {
            throw new BadRequestException("The extension does not support testing");
        }

        final ExtensionTestResult testResult = testable.test(runtimeConfig);

        final var response = TestExtensionResponse.builder()
                .checks(testResult.checks().stream()
                        .map(ExtensionsResource::convert)
                        .toList())
                .build();

        return Response.ok(response).build();
    }

    private Class<? extends ExtensionPoint> getExtensionPointClass(String extensionPointName) {
        return pluginManager.getExtensionPoints().stream()
                .filter(spec -> spec.name().equals(extensionPointName))
                .map(ExtensionPointMetadata::clazz)
                .findAny()
                .orElseThrow(NotFoundException::new);
    }

    private ExtensionFactory<?> getExtensionFactory(
            Class<? extends ExtensionPoint> extensionPointClass,
            String extensionName) {
        return pluginManager.getFactories(extensionPointClass).stream()
                .filter(factory -> factory.extensionName().equals(extensionName))
                .findAny()
                .orElseThrow(NotFoundException::new);
    }

    private JsonNode validateConfigAndResolveSecrets(String configJson, RuntimeConfigSpec configSpec) {
        final var configNode = configMapper.validateJson(configJson, configSpec);

        try {
            configMapper.resolveSecretRefs(configNode, configSpec, secretManager::getSecretValue);
        } catch (UnresolvableSecretException e) {
            throw new BadRequestException(e.getMessage());
        }

        return configNode;
    }

    private static org.dependencytrack.api.v2.model.ExtensionTestCheck convert(ExtensionTestCheck check) {
        return org.dependencytrack.api.v2.model.ExtensionTestCheck.builder()
                .name(check.name())
                .status(switch (check.status()) {
                    case FAILED -> org.dependencytrack.api.v2.model.ExtensionTestCheckStatus.FAILED;
                    case PASSED -> org.dependencytrack.api.v2.model.ExtensionTestCheckStatus.PASSED;
                    case SKIPPED -> org.dependencytrack.api.v2.model.ExtensionTestCheckStatus.SKIPPED;
                })
                .message(check.message())
                .build();
    }

}
