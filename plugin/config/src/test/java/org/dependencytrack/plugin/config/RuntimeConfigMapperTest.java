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

import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class RuntimeConfigMapperTest {

    private final RuntimeConfigMapper runtimeConfigMapper = new RuntimeConfigMapper();
    private final RuntimeConfigSpec configSpec = RuntimeConfigSpec.of(new TestRuntimeConfig());

    @Nested
    class SerializeTest {

        @Test
        void shouldSerializeToJson() {
            final var config = new TestRuntimeConfig()
                    .withRequiredString("foo")
                    .withEmailString("foo@example.com");

            final String configJson = runtimeConfigMapper.serialize(config);

            assertThatJson(configJson).isEqualTo(/* language=JSON */ """
                    {
                      "requiredString": "foo",
                      "emailString": "foo@example.com",
                      "secretsArray": []
                    }
                    """);
        }

        @Test
        void shouldThrowWhenConfigIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> runtimeConfigMapper.serialize(null))
                    .withMessage("config must not be null");
        }

    }

    @Nested
    class ValidateTest {

        @Test
        void shouldNotThrowWhenConfigIsValid() {
            final var config = new TestRuntimeConfig()
                    .withRequiredString("foo");

            assertThatNoException()
                    .isThrownBy(() -> runtimeConfigMapper.validate(config, configSpec));
        }

        @Test
        void shouldThrowWhenConfigIsInvalid() {
            final var config = new TestRuntimeConfig();

            assertThatExceptionOfType(RuntimeConfigSchemaValidationException.class)
                    .isThrownBy(() -> runtimeConfigMapper.validate(config, configSpec));
        }

        @Test
        void shouldThrowWhenConfigIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> runtimeConfigMapper.validate(null, configSpec))
                    .withMessage("config must not be null");
        }

        @Test
        void shouldThrowWhenConfigSpecIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> runtimeConfigMapper.validate(new TestRuntimeConfig(), null))
                    .withMessage("configSpec must not be null");
        }

    }

    @Nested
    class ValidateJsonTest {

        @Test
        void shouldNotThrowWhenConfigJsonIsValid() {
            assertThatNoException()
                    .isThrownBy(() -> runtimeConfigMapper.validateJson(/* language=JSON */ """
                                    {
                                      "requiredString": "foo",
                                      "emailString": "foo@example.com"
                                    }
                                    """,
                            configSpec));
        }

        @Test
        void shouldThrowWhenConfigJsonIsInvalid() {
            assertThatExceptionOfType(RuntimeConfigSchemaValidationException.class)
                    .isThrownBy(() -> runtimeConfigMapper.validateJson(/* language=JSON */ """
                                    {
                                      "requiredString": null
                                    }
                                    """,
                            configSpec));
        }

    }

    @Nested
    class ResolveSecretRefsTest {

        @Test
        void shouldResolveSecretRefs() {
            final JsonNode configNode = runtimeConfigMapper.validateJson(/* language=JSON */ """
                            {
                              "requiredString": "foo",
                              "secretString": "mySecret",
                              "secretsArray": [
                                "mySecret"
                              ],
                              "nestedObject": {
                                "nestedSecretString": "mySecret"
                              }
                            }
                            """,
                    configSpec);

            runtimeConfigMapper.resolveSecretRefs(configNode, configSpec, mySecret -> "mySecretValue");

            assertThatJson(configNode.toString()).isEqualTo(/* language=JSON */ """
                    {
                      "requiredString": "foo",
                      "secretString": "mySecretValue",
                      "secretsArray": [
                        "mySecretValue"
                      ],
                      "nestedObject": {
                        "nestedSecretString": "mySecretValue"
                      }
                    }
                    """);
        }

        @Test
        void shouldThrowWhenSecretCannotBeResolved() {
            final JsonNode configNode = runtimeConfigMapper.validateJson(/* language=JSON */ """
                            {
                              "requiredString": "foo",
                              "secretString": "mySecret"
                            }
                            """,
                    configSpec);

            assertThatExceptionOfType(UnresolvableSecretException.class)
                    .isThrownBy(() -> runtimeConfigMapper.resolveSecretRefs(configNode, configSpec, mySecret -> null))
                    .withMessage("Secret 'mySecret' referenced at path '/secretString' does not exist");
        }

    }


}