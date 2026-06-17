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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ApiKeyDecoderTest {

    @Test
    void shouldDecodeNewApiKeyFormat() {
        final String rawKey = "alpine_b0RmmAbC_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";
        final ApiKey decodedKey = ApiKeyDecoder.decode(rawKey);

        assertThat(decodedKey).isNotNull();
        assertThat(decodedKey.getPublicId()).isEqualTo("b0RmmAbC");
        assertThat(decodedKey.getSecret()).isEqualTo("tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
        assertThat(decodedKey.getSecretHash()).isEqualTo("95072472e6928f97b069fc3ec59b87532a7e97898a404053043536082d3f7463");
        assertThat(decodedKey.getKey()).isEqualTo("alpine_b0RmmAbC_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
        assertThat(decodedKey.isLegacy()).isFalse();
    }

    @Test
    void shouldDecodeNewApiKeyFormatWithLegacyPublicId() {
        final String rawKey = "alpine_b0Rmm_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";
        final ApiKey decodedKey = ApiKeyDecoder.decode(rawKey);

        assertThat(decodedKey).isNotNull();
        assertThat(decodedKey.getPublicId()).isEqualTo("b0Rmm");
        assertThat(decodedKey.getSecret()).isEqualTo("tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
        assertThat(decodedKey.getSecretHash()).isEqualTo("95072472e6928f97b069fc3ec59b87532a7e97898a404053043536082d3f7463");
        assertThat(decodedKey.getKey()).isEqualTo("alpine_b0Rmm_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
        assertThat(decodedKey.isLegacy()).isFalse();
    }

    @Test
    void shouldDecodeLegacyApiKeyFormat() {
        final String rawKey = "tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";
        final ApiKey decodedKey = ApiKeyDecoder.decode(rawKey);

        assertThat(decodedKey).isNotNull();
        assertThat(decodedKey.getPublicId()).isEqualTo("tl3ZW");
        assertThat(decodedKey.getSecret()).isEqualTo("y61Znje6jNl7PwEQxSn4bSxpZBA");
        assertThat(decodedKey.getSecretHash()).isEqualTo("69e36a08fecf861b7ac65c7cc799c4b352bfd9c54ed4214d60fa3aba153af25c");
        assertThat(decodedKey.getKey()).isEqualTo("tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
        assertThat(decodedKey.isLegacy()).isTrue();
    }

    @Test
    void shouldDecodeLegacyApiKeyWithPrefix() {
        final String rawKey = "alpine_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";
        final ApiKey decodedKey = ApiKeyDecoder.decode(rawKey);

        assertThat(decodedKey).isNotNull();
        assertThat(decodedKey.getPublicId()).isEqualTo("tl3ZW");
        assertThat(decodedKey.getSecret()).isEqualTo("y61Znje6jNl7PwEQxSn4bSxpZBA");
        assertThat(decodedKey.getSecretHash()).isEqualTo("69e36a08fecf861b7ac65c7cc799c4b352bfd9c54ed4214d60fa3aba153af25c");
        assertThat(decodedKey.getKey()).isEqualTo("alpine_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA");
        assertThat(decodedKey.isLegacy()).isTrue();
    }

    @Test
    void shouldThrowWhenKeyIsNull() {
        assertThatExceptionOfType(InvalidApiKeyFormatException.class)
                .isThrownBy(() -> ApiKeyDecoder.decode(null))
                .withMessage("Provided API key is null");
    }

    @Test
    void shouldThrowWhenKeyHasInvalidFormat() {
        final String rawKey = "alpine_foo_bar_b0Rmm_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";

        assertThatExceptionOfType(InvalidApiKeyFormatException.class)
                .isThrownBy(() -> ApiKeyDecoder.decode(rawKey))
                .withMessage("Expected exactly 3 parts, but got 5");
    }

    @Test
    void shouldThrowWhenPublicIdHasInvalidFormat() {
        final String rawKey = "alpine_b0Rmm66_tl3ZWy61Znje6jNl7PwEQxSn4bSxpZBA";

        assertThatExceptionOfType(InvalidApiKeyFormatException.class)
                .isThrownBy(() -> ApiKeyDecoder.decode(rawKey))
                .withMessage("Expected public ID of 8 or 5 characters, but got 7");
    }

    @Test
    void shouldThrowWhenKeyPartHasInvalidFormat() {
        final String rawKey = "alpine_b0Rmm_foobarbaz";

        assertThatExceptionOfType(InvalidApiKeyFormatException.class)
                .isThrownBy(() -> ApiKeyDecoder.decode(rawKey))
                .withMessage("Expected secret of 32 or 27 characters, but got 9");
    }

}