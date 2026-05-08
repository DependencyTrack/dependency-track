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
package org.dependencytrack.secret.management.env;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.secret.management.ListSecretsRequest;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * @since 5.0.0
 */
final class EnvSecretManager implements SecretManager {

    private final Map<String, String> secretValueByName;
    private final PageTokenEncoder pageTokenEncoder;

    EnvSecretManager(
            Map<String, String> secretValueByName,
            PageTokenEncoder pageTokenEncoder) {
        this.secretValueByName = secretValueByName;
        this.pageTokenEncoder = pageTokenEncoder;
    }

    @Override
    public String name() {
        return "env";
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public void createSecret(String name, @Nullable String description, String value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean updateSecret(String name, @Nullable String description, @Nullable String value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void deleteSecret(String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public @Nullable SecretMetadata getSecretMetadata(String name) {
        return secretValueByName.keySet().stream()
                .filter(name::equals)
                .map(secretName -> new SecretMetadata(secretName, null, null, null))
                .findAny()
                .orElse(null);
    }

    @Override
    public @Nullable String getSecretValue(String name) {
        return secretValueByName.get(name);
    }

    record ListSecretsPageToken(String lastName) implements PageToken {
    }

    @Override
    public Page<SecretMetadata> listSecretMetadata(ListSecretsRequest request) {
        final var pageTokenValue = pageTokenEncoder.decode(request.pageToken(), ListSecretsPageToken.class);

        final String searchText = request.searchText() != null
                ? request.searchText().toLowerCase()
                : null;

        final Predicate<String> filterPredicate =
                secretName -> searchText == null || secretName.toLowerCase().startsWith(searchText);

        final long totalCount = secretValueByName.keySet().stream()
                .filter(filterPredicate)
                .count();

        final List<SecretMetadata> allMatching = secretValueByName.keySet().stream()
                .sorted()
                .filter(name -> pageTokenValue == null || name.compareTo(pageTokenValue.lastName()) > 0)
                .filter(filterPredicate)
                .limit(request.limit() + 1)
                .map(name -> new SecretMetadata(name, null, null, null))
                .toList();

        final List<SecretMetadata> resultItems = allMatching.size() > request.limit()
                ? allMatching.subList(0, request.limit())
                : allMatching;

        final String nextPageToken = allMatching.size() > request.limit()
                ? pageTokenEncoder.encode(new ListSecretsPageToken(resultItems.getLast().name()))
                : null;

        return new Page<>(resultItems, nextPageToken)
                .withTotalCount(totalCount, Page.TotalCount.Type.EXACT);
    }

}
