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
package org.dependencytrack.v4migrator.transform;

import java.util.ArrayList;
import java.util.List;

/**
 * Splits a PostgreSQL SQL script into individual statements at top-level {@code ;}.
 *
 * <p>Aware of the following lexical contexts where {@code ;} must be ignored:
 * <ul>
 *   <li>Line comments ({@code -- … <eol>}).</li>
 *   <li>Block comments ({@code /* … *}{@code /}), with nesting.</li>
 *   <li>Single-quoted strings ({@code '…'}) with embedded {@code ''} escape.</li>
 *   <li>Double-quoted identifiers ({@code "…"}) with embedded {@code ""} escape.</li>
 *   <li>Dollar-quoted strings ({@code $tag$ … $tag$}), used by {@code DO $$ … $$} blocks.</li>
 * </ul>
 */
final class SqlStatementSplitter {

    private SqlStatementSplitter() {
    }

    static List<String> split(final String sql) {
        final List<String> out = new ArrayList<>();
        final StringBuilder current = new StringBuilder();
        final int n = sql.length();
        int i = 0;
        while (i < n) {
            final char c = sql.charAt(i);

            // Line comment
            if (c == '-' && i + 1 < n && sql.charAt(i + 1) == '-') {
                final int eol = sql.indexOf('\n', i);
                final int end = eol == -1 ? n : eol;
                current.append(sql, i, end);
                i = end;
                continue;
            }

            // Block comment (nested-aware)
            if (c == '/' && i + 1 < n && sql.charAt(i + 1) == '*') {
                int depth = 1;
                int j = i + 2;
                current.append(c).append('*');
                while (j < n && depth > 0) {
                    if (j + 1 < n && sql.charAt(j) == '/' && sql.charAt(j + 1) == '*') {
                        depth++;
                        current.append('/').append('*');
                        j += 2;
                    } else if (j + 1 < n && sql.charAt(j) == '*' && sql.charAt(j + 1) == '/') {
                        depth--;
                        current.append('*').append('/');
                        j += 2;
                    } else {
                        current.append(sql.charAt(j));
                        j++;
                    }
                }
                i = j;
                continue;
            }

            // Single-quoted string
            if (c == '\'') {
                current.append(c);
                i++;
                while (i < n) {
                    final char d = sql.charAt(i);
                    current.append(d);
                    i++;
                    if (d == '\'') {
                        if (i < n && sql.charAt(i) == '\'') {
                            current.append('\'');
                            i++;
                            continue;
                        }
                        break;
                    }
                }
                continue;
            }

            // Double-quoted identifier
            if (c == '"') {
                current.append(c);
                i++;
                while (i < n) {
                    final char d = sql.charAt(i);
                    current.append(d);
                    i++;
                    if (d == '"') {
                        if (i < n && sql.charAt(i) == '"') {
                            current.append('"');
                            i++;
                            continue;
                        }
                        break;
                    }
                }
                continue;
            }

            // Dollar-quoted string: $tag$ ... $tag$ (tag may be empty: $$ ... $$).
            if (c == '$') {
                final int tagEnd = findClosingDollar(sql, i + 1);
                if (tagEnd > 0) {
                    final String tag = sql.substring(i, tagEnd + 1);
                    current.append(tag);
                    int j = tagEnd + 1;
                    final int close = sql.indexOf(tag, j);
                    if (close < 0) {
                        // No closing delimiter; treat the rest as one statement.
                        current.append(sql, j, n);
                        i = n;
                        continue;
                    }
                    current.append(sql, j, close).append(tag);
                    i = close + tag.length();
                    continue;
                }
            }

            // Top-level semicolon separator
            if (c == ';') {
                final String stmt = current.toString().trim();
                if (!stmt.isEmpty()) {
                    out.add(stmt);
                }
                current.setLength(0);
                i++;
                continue;
            }

            current.append(c);
            i++;
        }
        final String tail = current.toString().trim();
        if (!tail.isEmpty()) {
            out.add(tail);
        }
        return out;
    }

    /**
     * Given the index just past a {@code $}, find the closing {@code $} for a dollar-quote tag.
     * Returns the index of the closing dollar, or -1 if the run does not look like a valid tag.
     */
    private static int findClosingDollar(final String sql, final int start) {
        final int n = sql.length();
        int i = start;
        while (i < n) {
            final char c = sql.charAt(i);
            if (c == '$') {
                return i;
            }
            if (!(Character.isLetterOrDigit(c) || c == '_')) {
                return -1;
            }
            i++;
        }
        return -1;
    }
}
