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
package org.dependencytrack.v4migrator.source;

public enum SourceFlavor {

    POSTGRESQL("public"),
    MSSQL("dbo");

    private final String defaultSchema;

    SourceFlavor(final String defaultSchema) {
        this.defaultSchema = defaultSchema;
    }

    public String defaultSchema() {
        return defaultSchema;
    }

    public static SourceFlavor fromJdbcUrl(final String jdbcUrl) {
        if (jdbcUrl == null) {
            throw new IllegalArgumentException("Source JDBC URL is required");
        }
        if (jdbcUrl.startsWith("jdbc:postgresql:")) {
            return POSTGRESQL;
        }
        if (jdbcUrl.startsWith("jdbc:sqlserver:")) {
            return MSSQL;
        }
        // JDBC URLs can embed credentials in the query string; only echo the scheme.
        final int sep = indexOfAny(jdbcUrl, '?', ';');
        final String safe = sep < 0 ? jdbcUrl : jdbcUrl.substring(0, sep);
        throw new IllegalArgumentException(
            "Unsupported source JDBC URL '" + safe
                + "': expected jdbc:postgresql: or jdbc:sqlserver:");
    }

    private static int indexOfAny(final String s, final char a, final char b) {
        for (int i = 0; i < s.length(); i++) {
            final char c = s.charAt(i);
            if (c == a || c == b) {
                return i;
            }
        }
        return -1;
    }
}
