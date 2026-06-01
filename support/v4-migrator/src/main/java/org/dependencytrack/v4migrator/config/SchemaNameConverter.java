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
package org.dependencytrack.v4migrator.config;

import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.TypeConversionException;

import java.util.regex.Pattern;

/**
 * Picocli converter for schema-name options. Schema names are splice-formatted into SQL
 * throughout the migrator, always inside a double-quoted identifier position ({@code "%s"}),
 * and in a few preflight probes additionally inside a single-quoted string literal
 * (e.g. {@code to_regclass('"%s"."PROJECT"')}). The validator therefore accepts the full
 * quoted-identifier alphabet but rejects characters that could break out of either quoting
 * layer: the double-quote, the single-quote / apostrophe, NUL, and other control characters.
 *
 * <p>Length is capped at 63 bytes ({@code NAMEDATALEN - 1} on PostgreSQL; SQL Server's 128
 * limit is a superset).
 */
public final class SchemaNameConverter implements ITypeConverter<String> {

    private static final Pattern PATTERN = Pattern.compile("^[^\"'\\x00-\\x1F\\x7F]{1,63}$");

    @Override
    public String convert(final String value) {
        if (value == null || !PATTERN.matcher(value).matches()) {
            throw new TypeConversionException(
                "must be 1-63 characters and contain no quote or control characters; got '"
                    + value + "'");
        }
        return value;
    }
}
