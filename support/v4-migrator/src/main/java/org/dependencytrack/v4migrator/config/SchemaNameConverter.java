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
 * throughout the migrator, so anything outside the unquoted-identifier syntax would allow
 * injection.
 *
 * <p>PostgreSQL unquoted-identifier syntax minus the locale-dependent letter ranges: leading
 * letter or underscore, followed by letters, digits, underscores, or {@code $}. Max length
 * 63 bytes ({@code NAMEDATALEN - 1}).
 */
public final class SchemaNameConverter implements ITypeConverter<String> {

    private static final Pattern PATTERN = Pattern.compile("^[A-Za-z_][A-Za-z0-9_$]{0,62}$");

    @Override
    public String convert(final String value) {
        if (value == null || !PATTERN.matcher(value).matches()) {
            throw new TypeConversionException(
                "must match [A-Za-z_][A-Za-z0-9_$]* and be 1-63 characters; got '" + value + "'");
        }
        return value;
    }
}
