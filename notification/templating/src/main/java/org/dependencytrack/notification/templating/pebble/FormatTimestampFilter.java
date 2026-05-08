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
package org.dependencytrack.notification.templating.pebble;

import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import io.pebbletemplates.pebble.extension.Filter;
import io.pebbletemplates.pebble.template.EvaluationContext;
import io.pebbletemplates.pebble.template.PebbleTemplate;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * @since 5.0.0
 */
final class FormatTimestampFilter implements Filter {

    private static final String DEFAULT_PATTERN = "yyyy-MM-dd'T'HH:mm:ssX";

    @Override
    public Object apply(
            Object input,
            Map<String, Object> args,
            PebbleTemplate self,
            EvaluationContext context,
            int lineNumber) {
        if (!(input instanceof Timestamp ts)) {
            return input;
        }

        final String pattern = args.get("pattern") instanceof String p ? p : DEFAULT_PATTERN;
        final DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern).withZone(ZoneOffset.UTC);
        return formatter.format(Instant.ofEpochMilli(Timestamps.toMillis(ts)));
    }

    @Override
    public List<String> getArgumentNames() {
        return List.of("pattern");
    }

}
