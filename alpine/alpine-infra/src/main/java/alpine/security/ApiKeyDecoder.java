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

/**
 * @since 3.2.0
 */
public final class ApiKeyDecoder {

    private ApiKeyDecoder() {
    }

    /**
     * @param apiKeyString The API key string to decode.
     * @return The decoded {@link ApiKey}.
     * @throws InvalidApiKeyFormatException When the provided API key has an invalid format.
     */
    public static ApiKey decode(final String apiKeyString) {
        if (apiKeyString == null) {
            throw new InvalidApiKeyFormatException("Provided API key is null");
        }

        final var apiKey = new ApiKey();
        apiKey.setKey(apiKeyString);

        if (apiKeyString.length() == ApiKey.LEGACY_FULL_KEY_LENGTH) {
            apiKey.setPublicId(apiKeyString.substring(0, ApiKey.LEGACY_PUBLIC_ID_LENGTH));
            apiKey.setSecret(apiKeyString.substring(ApiKey.LEGACY_PUBLIC_ID_LENGTH));
            apiKey.setSecretHash(ApiKeyGenerator.hashSecret(apiKey.getSecret()));
            apiKey.setLegacy(true);
            return apiKey;
        } else if (apiKeyString.length() == ApiKey.LEGACY_WITH_PREFIX_FULL_KEY_LENGTH) {
            apiKey.setPublicId(apiKeyString.substring(ApiKey.PREFIX_LENGTH, ApiKey.PREFIX_LENGTH + ApiKey.LEGACY_PUBLIC_ID_LENGTH));
            apiKey.setSecret(apiKeyString.substring(ApiKey.PREFIX_LENGTH + ApiKey.LEGACY_PUBLIC_ID_LENGTH));
            apiKey.setSecretHash(ApiKeyGenerator.hashSecret(apiKey.getSecret()));
            apiKey.setLegacy(true);
            return apiKey;
        }

        final String[] parts = apiKeyString.split(String.valueOf(ApiKey.API_KEY_SEPARATOR));
        if (parts.length != 3) {
            throw new InvalidApiKeyFormatException("Expected exactly 3 parts, but got " + parts.length);
        } else if (parts[1].length() != ApiKey.PUBLIC_ID_LENGTH
                   && parts[1].length() != ApiKey.LEGACY_PUBLIC_ID_LENGTH) {
            throw new InvalidApiKeyFormatException(
                    "Expected public ID of %d or %d characters, but got %d".formatted(
                            ApiKey.PUBLIC_ID_LENGTH, ApiKey.LEGACY_PUBLIC_ID_LENGTH, parts[1].length()));
        } else if (parts[2].length() != ApiKey.API_KEY_LENGTH
                   && parts[2].length() != ApiKey.API_KEY_LENGTH - ApiKey.LEGACY_PUBLIC_ID_LENGTH) {
            // Legacy keys that were migrated to the new format have their first $PUBLIC_ID_LENGTH
            // characters re-purposed as public ID, and are thus shorter than normal.
            throw new InvalidApiKeyFormatException(
                    "Expected secret of %d or %d characters, but got %d".formatted(
                            ApiKey.API_KEY_LENGTH, ApiKey.API_KEY_LENGTH - ApiKey.LEGACY_PUBLIC_ID_LENGTH, parts[2].length()));
        }

        apiKey.setPublicId(parts[1]);
        apiKey.setSecret(parts[2]);
        apiKey.setSecretHash(ApiKeyGenerator.hashSecret(parts[2]));
        return apiKey;
    }

}
