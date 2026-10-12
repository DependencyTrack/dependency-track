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
package org.dependencytrack.util;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_MATCH_MODE;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_NAMES_REGEX;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * Utility class to identify internal components based on the configured group and name regular expressions.
 * <p>
 * RegEx patterns are loaded and compiled once upon first invocation of {@link #isInternal(Component)},
 * and then re-used for the lifetime of the {@link InternalComponentIdentifier} instance.
 *
 * @since 4.11.0
 */
@NotThreadSafe
public class InternalComponentIdentifier {

    private record Patterns(Pattern groupPattern, Pattern namePattern, String matchMode) {

        private boolean hasPattern() {
            return groupPattern != null || namePattern != null;
        }
    }

    private Patterns patterns;

    public boolean isInternal(final Component component) {
        final Patterns patterns = getPatterns();
        if (!patterns.hasPattern()) {
            return false;
        }

        final boolean matchesGroup;
        if (isNotBlank(component.getGroup()) && patterns.groupPattern() != null) {
            matchesGroup = patterns.groupPattern().matcher(component.getGroup()).matches();
        } else {
            matchesGroup = false;
        }

        final boolean matchesName;
        if (isNotBlank(component.getName()) && patterns.namePattern() != null) {
            matchesName = patterns.namePattern().matcher(component.getName()).matches();
        } else {
            matchesName = false;
        }

        if ("AND".equalsIgnoreCase(patterns.matchMode())) {
            final boolean groupOk = patterns.groupPattern() == null || matchesGroup;
            final boolean nameOk = patterns.namePattern() == null || matchesName;
            return groupOk && nameOk;
        }

        return matchesGroup || matchesName;
    }

    public boolean hasPatterns() {
        return getPatterns().hasPattern();
    }

    private Patterns getPatterns() {
        if (patterns == null) {
            patterns = loadPatterns();
        }

        return patterns;
    }

    private static Patterns loadPatterns() {
        return withJdbiHandle(handle -> {
            final var dao = handle.attach(ConfigPropertyDao.class);
            return new Patterns(
                    dao.getOptionalValue(INTERNAL_COMPONENTS_GROUPS_REGEX)
                            .map(InternalComponentIdentifier::tryCompilePattern)
                            .orElse(null),
                    dao.getOptionalValue(INTERNAL_COMPONENTS_NAMES_REGEX)
                            .map(InternalComponentIdentifier::tryCompilePattern)
                            .orElse(null),
                    dao.getOptionalValue(INTERNAL_COMPONENTS_MATCH_MODE)
                            .map(StringUtils::trimToNull)
                            .orElse(INTERNAL_COMPONENTS_MATCH_MODE.getDefaultPropertyValue()));
        });
    }

    private static @Nullable Pattern tryCompilePattern(String value) {
        final String valueTrimmed = StringUtils.trimToNull(value);
        if (valueTrimmed == null) {
            return null;
        }

        return Pattern.compile(valueTrimmed);
    }
}
