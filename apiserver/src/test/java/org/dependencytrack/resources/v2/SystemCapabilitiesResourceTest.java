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

import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.capabilities.CapabilityProvider;
import org.dependencytrack.capabilities.SystemCapabilitiesAggregator;
import org.dependencytrack.secret.management.SecretManager;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;

import java.util.List;
import java.util.Map;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class SystemCapabilitiesResourceTest extends ResourceTest {

    private static final SecretManager SECRET_MANAGER_MOCK = mock(SecretManager.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(SECRET_MANAGER_MOCK).to(SecretManager.class);
                            bind(new SystemCapabilitiesAggregator(List.of(
                                    new SecretManagementProviderUnderTest(SECRET_MANAGER_MOCK)),
                                    /* serviceLocator */ null))
                                    .to(SystemCapabilitiesAggregator.class);
                        }
                    }));

    @AfterEach
    void afterEach() {
        Mockito.reset(SECRET_MANAGER_MOCK);
    }

    @Test
    void shouldReturnUnauthorizedWhenNoCredentials() {
        final Response response = jersey
                .target("/internal/system-capabilities")
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldReturnCapabilitiesWhenAuthenticated() {
        doReturn(false).when(SECRET_MANAGER_MOCK).isReadOnly();

        final Response response = jersey
                .target("/internal/system-capabilities")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "capabilities": {
                    "secret_management": {
                      "read_only": false
                    }
                  }
                }
                """);
    }

    @Test
    void shouldReflectReadOnlySecretManager() {
        doReturn(true).when(SECRET_MANAGER_MOCK).isReadOnly();

        final Response response = jersey
                .target("/internal/system-capabilities")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "capabilities": {
                    "secret_management": {
                      "read_only": true
                    }
                  }
                }
                """);
    }

    private static final class SecretManagementProviderUnderTest implements CapabilityProvider {

        private final SecretManager secretManager;

        SecretManagementProviderUnderTest(final SecretManager secretManager) {
            this.secretManager = secretManager;
        }

        @Override
        public @NonNull String namespace() {
            return "secret_management";
        }

        @Override
        public @NonNull Map<String, Object> capabilities() {
            return Map.of("read_only", secretManager.isReadOnly());
        }

    }

}
