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

import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.Testable;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSchemaSource;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.secret.TestSecretManager;
import org.dependencytrack.secret.management.SecretManager;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.http.HttpClient;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ExtensionsResourceTest extends ResourceTest {

    private static PluginManager pluginManager;
    private static SecretManager secretManager;

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bindFactory(() -> pluginManager).to(PluginManager.class);
                            bindFactory(() -> secretManager).to(SecretManager.class);
                        }
                    }));

    @BeforeAll
    static void beforeAll() {
        secretManager = new TestSecretManager();
    }

    @BeforeEach
    void beforeEach() {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                secretManager::getSecretValue,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(DummyExtensionPoint.class));
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void listExtensionPointsShouldListAllExtensionPoints() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new DummyExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey
                .target("/extension-points")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "name": "dummy"
                    }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    void listExtensionsShouldListAllExtensions() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new DummyExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey
                .target("/extension-points/dummy/extensions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items":[
                    {
                      "name": "dummy-extension",
                      "configurable": true,
                      "testable": false
                    }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    void listExtensionsShouldReturnNotFoundWhenExtensionPointDoesNotExist() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey
                .target("/extension-points/doesNotExist/extensions")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "type": "about:blank",
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    void getExtensionConfigShouldReturnConfig() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new DummyExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        useJdbiTransaction(handle -> handle.createUpdate("""
                        INSERT INTO "EXTENSION_RUNTIME_CONFIG" ("EXTENSION_POINT", "EXTENSION", "CONFIG", "CREATED_AT")
                        VALUES (:extensionPoint, :extension, CAST(:config AS JSONB), NOW())
                        ON CONFLICT ("EXTENSION_POINT", "EXTENSION")
                        DO UPDATE SET "CONFIG" = EXCLUDED."CONFIG", "UPDATED_AT" = NOW()
                        """)
                .bind("extensionPoint", "dummy")
                .bind("extension", "dummy-extension")
                .bind("config", /* language=JSON */ """
                        {"requiredString": "yay!"}
                        """)
                .execute());

        final Response response = jersey
                .target("/extension-points/dummy/extensions/dummy-extension/config")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "config":{
                    "requiredString": "yay!"
                  }
                }
                """);
    }

    @Test
    void getExtensionConfigShouldReturnNotFoundWhenNotExists() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/doesNotExist/config")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "type": "about:blank",
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    void updateExtensionConfigShouldReturnNoContent() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new DummyExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/dummy-extension/config")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "requiredString": "foo",
                            "optionalString": "bar"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        final String savedConfig = withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "CONFIG" FROM "EXTENSION_RUNTIME_CONFIG"
                        WHERE "EXTENSION_POINT" = :extensionPoint AND "EXTENSION" = :extension
                        """)
                .bind("extensionPoint", "dummy")
                .bind("extension", "dummy-extension")
                .mapTo(String.class)
                .findOne()
                .orElse(null));
        assertThatJson(savedConfig).isEqualTo(/* language=JSON */ """
                {
                  "requiredString": "foo",
                  "optionalString": "bar"
                }
                """);
    }

    @Test
    void updateExtensionConfigShouldReturnNotModifiedWhenUnchanged() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new DummyExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        useJdbiTransaction(handle -> handle.createUpdate("""
                        INSERT INTO "EXTENSION_RUNTIME_CONFIG" ("EXTENSION_POINT", "EXTENSION", "CONFIG", "CREATED_AT")
                        VALUES (:extensionPoint, :extension, CAST(:config AS JSONB), NOW())
                        ON CONFLICT ("EXTENSION_POINT", "EXTENSION")
                        DO UPDATE SET "CONFIG" = EXCLUDED."CONFIG", "UPDATED_AT" = NOW()
                        """)
                .bind("extensionPoint", "dummy")
                .bind("extension", "dummy-extension")
                .bind("config", /* language=JSON */ """
                        {"requiredString": "foo", "optionalString": "bar"}
                        """)
                .execute());

        final Response response = jersey
                .target("/extension-points/dummy/extensions/dummy-extension/config")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "requiredString": "foo",
                            "optionalString": "bar"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(304);
        assertThat(getPlainTextBody(response)).isEmpty();
    }

    @Test
    void updateExtensionConfigShouldReturnBadRequestWhenInvalid() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new DummyExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/dummy-extension/config")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "requiredString": null
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "JSON Schema Validation Failed",
                  "detail": "The provided configuration failed JSON schema validation.",
                  "errors": [
                    {
                      "evaluation_path": "/properties/requiredString/type",
                      "schema_location": "https://example.com/schema/test#/properties/requiredString/type",
                      "instance_location": "/requiredString",
                      "keyword": "type",
                      "message": "null found, string expected"
                    }
                  ]
                }
                """);
    }

    @Test
    void updateExtensionConfigShouldReturnBadRequestWhenConfigValidationFails() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new ExtensionWithValidatorFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/extension-with-validator/config")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "outcome": "PASSED"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 400,
                  "type": "about:blank",
                  "title": "Config Validation Failed",
                  "detail": "Boom!"
                }
                """);
    }

    @Test
    void getExtensionConfigSchemaShouldReturnConfigSchema() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new DummyExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/dummy-extension/config-schema")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "$schema": "https://json-schema.org/draft/2020-12/schema",
                  "$id": "https://example.com/schema/test",
                  "type": "object",
                  "properties": {
                    "requiredString": {
                      "type": "string",
                      "description": "A required string"
                    },
                    "optionalString": {
                      "type": "string",
                      "description": "An optional string"
                    }
                  },
                  "required": [
                    "requiredString"
                  ]
                }
                """);
    }

    @Test
    void getExtensionConfigSchemaShouldReturnNoContentWhenExtensionHasNoSchema() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new NonConfigurableExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/non-configurable-extension/config-schema")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();
    }

    @Test
    void testExtensionShouldReturnTestResultWhenTestPassed() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestableExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/testable-extension/test")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "outcome": "PASSED"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "checks": [
                    {
                      "name": "name",
                      "status": "PASSED"
                    }
                  ]
                }
                """);
    }

    @Test
    void testExtensionShouldReturnTestResultWhenTestFailed() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestableExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/testable-extension/test")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "outcome": "FAILED"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "checks": [
                    {
                      "name": "name",
                      "status": "FAILED",
                      "message": "message"
                    }
                  ]
                }
                """);
    }

    @Test
    void testExtensionShouldReturnBadRequestWhenExtensionDoesNotSupportTesting() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new DummyExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/dummy-extension/test")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "requiredString": "foo"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 400,
                  "type": "about:blank",
                  "title": "Bad Request",
                  "detail": "The extension does not support testing"
                }
                """);
    }

    @Test
    void testExtensionShouldReturnBadRequestWhenConfigSchemaValidationFails() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestableExtensionFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/testable-extension/test")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "outcome": "invalid"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 400,
                  "type": "about:blank",
                  "title":"JSON Schema Validation Failed",
                  "detail": "The provided configuration failed JSON schema validation.",
                  "errors": [
                    {
                      "evaluation_path": "/properties/outcome/enum",
                      "instance_location": "/outcome",
                      "keyword": "enum",
                      "message": "does not have a value in the enumeration [\\"PASSED\\", \\"FAILED\\"]",
                      "schema_location": "https://example.com/schema/test#/properties/outcome/enum"
                    }
                  ]
                }
                """);
    }

    @Test
    void testExtensionShouldReturnBadRequestWhenConfigValidationFails() {
        pluginManager.loadPlugins(List.of(
                () -> List.of(new ExtensionWithValidatorFactory())));

        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey
                .target("/extension-points/dummy/extensions/extension-with-validator/test")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "config": {
                            "outcome": "PASSED"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 400,
                  "type": "about:blank",
                  "title": "Config Validation Failed",
                  "detail": "Boom!"
                }
                """);
    }

    @ExtensionPointSpec(name = "dummy")
    private interface DummyExtensionPoint extends ExtensionPoint {
    }

    private static class DummyExtension implements DummyExtensionPoint {
    }

    private record DummyRuntimeConfig(
            String requiredString,
            String optionalString) implements RuntimeConfig {
    }

    private static class DummyExtensionFactory implements ExtensionFactory<DummyExtensionPoint>, RuntimeConfigurable {

        @Override
        public @NonNull String extensionName() {
            return "dummy-extension";
        }

        @Override
        public @NonNull Class<? extends DummyExtensionPoint> extensionClass() {
            return DummyExtension.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public RuntimeConfigSpec runtimeConfigSpec() {
            final var defaultConfig = new DummyRuntimeConfig("test", null);
            return RuntimeConfigSpec.of(
                    defaultConfig,
                    new RuntimeConfigSchemaSource.Literal(/* language=JSON */ """
                            {
                              "$schema": "https://json-schema.org/draft/2020-12/schema",
                              "$id": "https://example.com/schema/test",
                              "type": "object",
                              "properties": {
                                "requiredString": {
                                  "type": "string",
                                  "description": "A required string"
                                },
                                "optionalString": {
                                  "type": "string",
                                  "description": "An optional string"
                                }
                              },
                              "required": [
                                "requiredString"
                              ]
                            }
                            """),
                    null);
        }

        @Override
        public void init(ServiceRegistry serviceRegistry) {
        }

        @Override
        public DummyExtensionPoint create() {
            return new DummyExtension();
        }

    }

    private static class NonConfigurableExtensionFactory implements ExtensionFactory<DummyExtensionPoint> {

        @Override
        public String extensionName() {
            return "non-configurable-extension";
        }

        @Override
        public Class<? extends DummyExtensionPoint> extensionClass() {
            return DummyExtension.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public void init(ServiceRegistry serviceRegistry) {
        }

        @Override
        public DummyExtensionPoint create() {
            return new DummyExtension();
        }

    }

    private record TestableRuntimeConfig(String outcome) implements RuntimeConfig {
    }

    private static class TestableExtensionFactory implements ExtensionFactory<DummyExtensionPoint>, RuntimeConfigurable, Testable {

        @Override
        public @NonNull String extensionName() {
            return "testable-extension";
        }

        @Override
        public Class<? extends DummyExtensionPoint> extensionClass() {
            return DummyExtension.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public void init(ServiceRegistry serviceRegistry) {
        }

        @Override
        public DummyExtensionPoint create() {
            return new DummyExtension();
        }

        @Override
        public ExtensionTestResult test(@Nullable RuntimeConfig runtimeConfig) {
            final var testConfig = (TestableRuntimeConfig) runtimeConfig;
            if ("PASSED".equals(testConfig.outcome())) {
                return ExtensionTestResult.ofChecks("name").pass("name");
            } else {
                return ExtensionTestResult.ofChecks("name").fail("name", "message");
            }
        }

        @Override
        public @Nullable RuntimeConfigSpec runtimeConfigSpec() {
            final var defaultConfig = new TestableRuntimeConfig(null);
            return RuntimeConfigSpec.of(
                    defaultConfig,
                    new RuntimeConfigSchemaSource.Literal(/* language=JSON */ """
                            {
                              "$schema": "https://json-schema.org/draft/2020-12/schema",
                              "$id": "https://example.com/schema/test",
                              "type": "object",
                              "properties": {
                                "outcome": {
                                  "type": "string",
                                  "enum": [
                                    "PASSED",
                                    "FAILED"
                                  ]
                                }
                              }
                            }
                            """),
                    null);
        }

    }

    private static class ExtensionWithValidatorFactory implements ExtensionFactory<DummyExtensionPoint>, RuntimeConfigurable, Testable {

        @Override
        public String extensionName() {
            return "extension-with-validator";
        }

        @Override
        public Class<? extends DummyExtensionPoint> extensionClass() {
            return DummyExtension.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public void init(ServiceRegistry serviceRegistry) {
        }

        @Override
        public @Nullable RuntimeConfigSpec runtimeConfigSpec() {
            final var defaultConfig = new TestableRuntimeConfig(null);
            return RuntimeConfigSpec.of(
                    defaultConfig,
                    new RuntimeConfigSchemaSource.Literal(/* language=JSON */ """
                            {
                              "$schema": "https://json-schema.org/draft/2020-12/schema",
                              "$id": "https://example.com/schema/test",
                              "type": "object",
                              "properties": {
                                "outcome": {
                                  "type": "string",
                                  "enum": [
                                    "PASSED",
                                    "FAILED"
                                  ]
                                }
                              }
                            }
                            """),
                    config -> {
                        if (config.outcome() != null) {
                            throw new InvalidRuntimeConfigException("Boom!");
                        }
                    });
        }

        @Override
        public ExtensionTestResult test(@Nullable RuntimeConfig runtimeConfig) {
            return ExtensionTestResult.ofChecks("name").pass("name");
        }

        @Override
        public DummyExtensionPoint create() {
            return new DummyExtension();
        }

    }

}