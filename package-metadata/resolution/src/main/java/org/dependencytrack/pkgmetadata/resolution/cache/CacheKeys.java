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
package org.dependencytrack.pkgmetadata.resolution.cache;

import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.StringJoiner;

/**
 * @since 5.0.0
 */
public final class CacheKeys {

    private CacheKeys() {
    }

    public static String build(String... segments) {
        return String.join(":", segments);
    }

    public static String build(PackageRepository repository, String... segments) {
        final var joiner = new StringJoiner(":");
        joiner.add(repository.url());

        final String credentialHash = hashCredentials(repository);
        if (credentialHash != null) {
            joiner.add(credentialHash);
        }

        for (final String segment : segments) {
            joiner.add(segment);
        }

        return joiner.toString();
    }

    public static String forRequest(String method, URI uri, @Nullable PackageRepository repository) {
        final var joiner = new StringJoiner(":");
        joiner.add(method);
        joiner.add(uri.toString());

        if (repository != null) {
            final String credentialHash = hashCredentials(repository);
            if (credentialHash != null) {
                joiner.add(credentialHash);
            }
        }

        return joiner.toString();
    }

    private static @Nullable String hashCredentials(PackageRepository repository) {
        if (repository.username() == null && repository.password() == null) {
            return null;
        }

        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        final String username = repository.username() != null
                ? repository.username()
                : "";
        final String password = repository.password() != null
                ? repository.password()
                : "";

        digest.update(username.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) ':');
        digest.update(password.getBytes(StandardCharsets.UTF_8));

        return HexFormat.of().formatHex(digest.digest(), 0, 8);
    }

}
