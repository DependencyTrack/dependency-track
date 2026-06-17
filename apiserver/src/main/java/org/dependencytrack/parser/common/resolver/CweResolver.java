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
package org.dependencytrack.parser.common.resolver;

import alpine.persistence.OrderDirection;
import alpine.persistence.PaginatedResult;
import alpine.persistence.Pagination;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Cwe;
import org.jspecify.annotations.Nullable;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Attempts to resolve an internal CWE object from a string
 * representation of a CWE.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class CweResolver {

    private static final CweResolver INSTANCE = new CweResolver();

    private CweResolver() {
    }

    public static CweResolver getInstance() {
        return INSTANCE;
    }

    /**
     * Lookups a CWE from the internal CWE dictionary. This method
     * does not query the database, but will return a Cwe object useful
     * for JSON serialization, but not for persistence.
     *
     * @param cweString the string to lookup
     * @return a Cwe object
     * @since 4.5.0
     */
    public Cwe lookup(final String cweString) {
        return lookup(parseCweString(cweString));
    }

    /**
     * Lookups a CWE from the internal CWE dictionary. This method
     * does not query the database, but will return a Cwe object useful
     * for JSON serialization, but not for persistence.
     *
     * @param cweId the cwe id to lookup
     * @return a Cwe object
     * @since 4.5.0
     */
    public Cwe lookup(final Integer cweId) {
        if (cweId != null) {
            final String cweName = CweDictionary.DICTIONARY.get(cweId);
            if (cweName != null) {
                final Cwe cwe = new Cwe();
                cwe.setCweId(cweId);
                cwe.setName(cweName);
                return cwe;
            }
        }
        return null;
    }

    /**
     * Parses a CWE string returning the CWE ID, or null.
     *
     * @param cweString the string to parse
     * @return a Cwe object
     */
    public Integer parseCweString(final String cweString) {
        if (StringUtils.isNotBlank(cweString)) {
            final String string = cweString.trim();
            String lookupString = "";
            if (string.startsWith("CWE-") && string.contains(" ")) {
                // This is likely to be in the following format:
                // CWE-264 Permissions, Privileges, and Access Controls
                lookupString = string.substring(4, string.indexOf(" "));
            } else if (string.startsWith("CWE-") && string.length() < 9) {
                // This is likely to be in the following format:
                // CWE-264
                lookupString = string.substring(4);
            } else if (string.length() < 5) {
                // This is likely to be in the following format:
                // 264
                lookupString = string;
            }
            try {
                return Integer.valueOf(lookupString);
            } catch (NumberFormatException e) {
                // throw it away
            }
        }
        return null;
    }

    public List<Cwe> all() {
        return CweDictionary.DICTIONARY.entrySet().stream()
                .map(dictEntry -> {
                    final var cwe = new Cwe();
                    cwe.setCweId(dictEntry.getKey());
                    cwe.setName(dictEntry.getValue());
                    return cwe;
                })
                .toList();
    }

    public PaginatedResult all(
            @Nullable String searchText,
            @Nullable String orderBy,
            @Nullable OrderDirection orderDirection,
            @Nullable Pagination pagination) {
        final String needle = (searchText != null && !searchText.isBlank())
                ? searchText.trim().toLowerCase(Locale.ROOT)
                : null;

        Stream<Map.Entry<Integer, String>> dictEntryStream =
                CweDictionary.DICTIONARY.entrySet().stream()
                        .filter(entry -> needle == null
                                || entry.getValue().toLowerCase(Locale.ROOT).contains(needle)
                                || ("cwe-" + entry.getKey()).contains(needle));

        if ("cweId".equals(orderBy)) {
            final Comparator<Map.Entry<Integer, String>> comparator =
                    orderDirection == OrderDirection.DESCENDING
                            ? Map.Entry.<Integer, String>comparingByKey().reversed()
                            : Map.Entry.comparingByKey();
            dictEntryStream = dictEntryStream.sorted(comparator);
        }

        final List<Map.Entry<Integer, String>> dictEntries = dictEntryStream.toList();
        final int total = dictEntries.size();

        final List<Map.Entry<Integer, String>> dictEntriesPage;
        if (pagination == null || !pagination.isPaginated()) {
            dictEntriesPage = dictEntries;
        } else {
            final int offset = Math.min(pagination.getOffset(), total);
            final int end = Math.min(offset + pagination.getLimit(), total);
            dictEntriesPage = dictEntries.subList(offset, end);
        }

        final List<Cwe> cwes = dictEntriesPage.stream()
                .map(entry -> {
                    final var cwe = new Cwe();
                    cwe.setCweId(entry.getKey());
                    cwe.setName(entry.getValue());
                    return cwe;
                })
                .toList();
        return new PaginatedResult().objects(cwes).total(total);
    }

}
