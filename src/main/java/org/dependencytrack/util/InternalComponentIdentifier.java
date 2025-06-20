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
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.QueryManager;

import java.util.Optional;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_NAMES_REGEX;

/**
 * Utility class to identify internal components based on the configured group and name regular expressions.
 * <p>
 * RegEx patterns are loaded and compiled once upon first invocation of {@link #isInternal(Component)},
 * and then re-used for the lifetime of the {@link InternalComponentIdentifier} instance.
 * <p>
 * Direct usage of this class is preferred over {@link InternalComponentIdentificationUtil#isInternalComponent(Component)}
 * in cases where multiple {@link Component}s are to be checked. This avoids redundant database queries and
 * (re-) compilation of RegEx patterns.
 *
 * @since 4.11.0
 */
public class InternalComponentIdentifier {

    private record Patterns(Pattern groupPattern, Pattern namePattern) {

        private boolean hasPattern() {
            return groupPattern != null || namePattern != null;
        }

    }

    private final Supplier<Patterns> patternsSupplier = Suppliers.memoize(InternalComponentIdentifier::loadPatterns);

    public boolean isInternal(final Component component) {
        final Patterns patterns = patternsSupplier.get();
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

        return matchesGroup || matchesName;
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

            return new Patterns(
                    tryCompilePattern(groupsRegexProperty).orElse(null),
                    tryCompilePattern(namesRegexProperty).orElse(null)
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
