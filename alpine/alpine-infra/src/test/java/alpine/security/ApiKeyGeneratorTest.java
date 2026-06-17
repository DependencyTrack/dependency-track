/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.security;

import alpine.model.ApiKey;
import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class ApiKeyGeneratorTest {

    @Test
    void shouldGenerateApiKey() {
        final ApiKey apiKey = ApiKeyGenerator.generate(null);
        assertThat(apiKey.getPublicId()).matches("^[A-Za-z_0-9]{8}$");
        assertThat(apiKey.getSecret()).matches("^[A-Za-z0-9]{32}$");
        assertThat(apiKey.getSecretHash()).matches("^[a-z0-9]{64}$");
        assertThat(apiKey.getKey()).matches("^alpine_%s_%s$".formatted(
                Pattern.quote(apiKey.getPublicId()), Pattern.quote(apiKey.getSecret())));
    }

    @Test
    void shouldUseProvidedPublicId() {
        final ApiKey apiKey = ApiKeyGenerator.generate("b0RmmAbC");
        assertThat(apiKey.getPublicId()).isEqualTo("b0RmmAbC");
        assertThat(apiKey.getSecret()).matches("^[A-Za-z0-9]{32}$");
        assertThat(apiKey.getSecretHash()).matches("^[a-z0-9]{64}$");
        assertThat(apiKey.getKey()).matches("^alpine_b0RmmAbC_%s$".formatted(Pattern.quote(apiKey.getSecret())));
    }

    @Test
    void shouldUseProvidedLegacyPublicId() {
        final ApiKey apiKey = ApiKeyGenerator.generate("b0Rmm");
        assertThat(apiKey.getPublicId()).isEqualTo("b0Rmm");
        assertThat(apiKey.getSecret()).matches("^[A-Za-z0-9]{32}$");
        assertThat(apiKey.getSecretHash()).matches("^[a-z0-9]{64}$");
        assertThat(apiKey.getKey()).matches("^alpine_b0Rmm_%s$".formatted(Pattern.quote(apiKey.getSecret())));
    }

    @Test
    void shouldThrowWhenProvidedPublicIdIsInvalid() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> ApiKeyGenerator.generate("foo"))
                .withMessage("Expected provided public ID foo to be null or having length of 8 or 5, but has length of 3");
    }

}
