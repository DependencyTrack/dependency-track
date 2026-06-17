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

import alpine.model.ConfigProperty;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.QueryManager;

import javax.annotation.concurrent.NotThreadSafe;
import java.util.Optional;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_MATCH_MODE;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_NAMES_REGEX;

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
        try (final var qm = new QueryManager()) {
            final ConfigProperty groupsRegexProperty = qm.getConfigProperty(
                    INTERNAL_COMPONENTS_GROUPS_REGEX.getGroupName(),
                    INTERNAL_COMPONENTS_GROUPS_REGEX.getPropertyName()
            );
            final ConfigProperty namesRegexProperty = qm.getConfigProperty(
                    INTERNAL_COMPONENTS_NAMES_REGEX.getGroupName(),
                    INTERNAL_COMPONENTS_NAMES_REGEX.getPropertyName()
            );
            final ConfigProperty matchModeProperty = qm.getConfigProperty(
                    INTERNAL_COMPONENTS_MATCH_MODE.getGroupName(),
                    INTERNAL_COMPONENTS_MATCH_MODE.getPropertyName()
            );

            return new Patterns(
                    tryCompilePattern(groupsRegexProperty).orElse(null),
                    tryCompilePattern(namesRegexProperty).orElse(null),
                    Optional.ofNullable(matchModeProperty)
                            .map(ConfigProperty::getPropertyValue)
                            .map(StringUtils::trimToNull)
                            .orElse(INTERNAL_COMPONENTS_MATCH_MODE.getDefaultPropertyValue())
            );
        }
    }

    private static Optional<Pattern> tryCompilePattern(final ConfigProperty property) {
        return Optional.ofNullable(property)
                .map(ConfigProperty::getPropertyValue)
                .map(StringUtils::trimToNull)
                .map(Pattern::compile);
    }

}