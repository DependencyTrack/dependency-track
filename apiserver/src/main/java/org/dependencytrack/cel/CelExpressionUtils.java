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
package org.dependencytrack.cel;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CelExpressionUtils {

    private static final Pattern DURATION_DAYS_PATTERN = Pattern.compile("duration\\(\"(\\d+)d\"\\)");

    private CelExpressionUtils() {
    }

    public static String normalizeDurationDays(String expressionSrc) {
        // We migrated from https://github.com/projectnessie/cel-java
        // to https://github.com/google/cel-java. The former supported
        // durations to be provided in days (e.g. "5d"), but the latter
        // doesn't. To avoid breaking existing expressions, we transparently
        // rewrite durations, e.g. "5d" = "120h".
        final Matcher matcher = DURATION_DAYS_PATTERN.matcher(expressionSrc);
        return matcher.replaceAll(match -> {
            final long days = Long.parseLong(match.group(1));
            return "duration(\"%dh\")".formatted(Math.multiplyExact(days, 24));
        });
    }

}
