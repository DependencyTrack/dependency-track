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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

import static java.util.Objects.requireNonNullElseGet;

/**
 * Class used to securely generate API keys.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public final class ApiKeyGenerator {

    private static final char[] VALID_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456879".toCharArray();

    /**
     * Private constructor
     */
    private ApiKeyGenerator() {
    }

    /**
     * @param publicId The public ID of an existing key. May be {@code null}.
     * @return A newly generated, non-persistent {@link ApiKey}.
     * @throws IllegalArgumentException When {@code publicId} has an invalid format.
     * @since 3.2.0
     */
    public static ApiKey generate(String publicId) {
        if (publicId != null
            && publicId.length() != ApiKey.PUBLIC_ID_LENGTH
            && publicId.length() != ApiKey.LEGACY_PUBLIC_ID_LENGTH) {
            throw new IllegalArgumentException(
                    "Expected provided public ID %s to be null or having length of %d or %d, but has length of %d".formatted(
                            publicId, ApiKey.PUBLIC_ID_LENGTH, ApiKey.LEGACY_PUBLIC_ID_LENGTH, publicId.length()));
        }

        // NB: The default prefix value has historically been "alpine_".
        // Since the new API key format uses "_" as separator, trim any occurrence
        // of it from the configured prefix to ensure consistent formatting.
        // "alpine_" effectively becomes "alpine".
        final String prefix = ApiKey.PREFIX.replaceAll("_*$", "");
        publicId = requireNonNullElseGet(publicId, () -> generateSecret(ApiKey.PUBLIC_ID_LENGTH));
        final String plainTextSecret = generateSecret(ApiKey.API_KEY_LENGTH);
        final String secretHash = hashSecret(plainTextSecret);
        final String fullKey = String.join(String.valueOf(ApiKey.API_KEY_SEPARATOR), prefix, publicId, plainTextSecret);

        final var apiKey = new ApiKey();
        apiKey.setPublicId(publicId);
        apiKey.setSecret(plainTextSecret);
        apiKey.setSecretHash(secretHash);
        apiKey.setKey(fullKey);
        return apiKey;
    }

    /**
     * @return A newly generated, non-persistent {@link ApiKey}.
     * @see #generate(String)
     * @since 3.2.0
     */
    public static ApiKey generate() {
        return generate(/* publicId */ null);
    }

    /**
     * @param secretLength Length of the secret to generate.
     * @return The generated secret.
     * @since 3.2.0
     */
    public static String generateSecret(final int secretLength) {
        final SecureRandom secureRandom = new SecureRandom();
        final char[] buff = new char[secretLength];
        for (int i = 0; i < secretLength; ++i) {
            if (i % 10 == 0) {
                secureRandom.setSeed(secureRandom.nextLong());
            }
            buff[i] = VALID_CHARACTERS[secureRandom.nextInt(VALID_CHARACTERS.length)];
        }

        return String.valueOf(buff);
    }

    /**
     * @param plainTextSecret The plain text secret to hash.
     * @return The hashed, hex-encoded value.
     * @since 3.2.0
     */
    public static String hashSecret(final String plainTextSecret) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            final byte[] secretHash = digest.digest(plainTextSecret.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(secretHash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
