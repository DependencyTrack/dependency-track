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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import alpine.model.ConfigProperty;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;

import java.util.regex.Pattern;

/**
 * @author nscuro
 * @since 3.7.0
 */
public final class InternalComponentIdentificationUtil {

    private InternalComponentIdentificationUtil() {
    }

    public static boolean isInternalComponent(final Component component, final QueryManager qm) {
        return isInternalGroup(component.getGroup(), qm) || isInternalName(component.getName(), qm);
    }

    private static boolean isInternalGroup(final String group, final QueryManager qm) {
        if (StringUtils.trimToNull(group) == null) {
            return false;
        }

        final ConfigProperty internalGroupsRegexProperty = qm.getConfigProperty(
                ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX.getGroupName(),
                ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX.getPropertyName()
        );
        if (internalGroupsRegexProperty == null || StringUtils.trimToNull(internalGroupsRegexProperty.getPropertyValue()) == null) {
            return false;
        }

        return Pattern.matches(StringUtils.trimToNull(internalGroupsRegexProperty.getPropertyValue()), group);
    }

    private static boolean isInternalName(final String name, final QueryManager qm) {
        if (StringUtils.trimToNull(name) == null) {
            return false;
        }

        final ConfigProperty internalNamesRegexProperty = qm.getConfigProperty(
                ConfigPropertyConstants.INTERNAL_COMPONENTS_NAMES_REGEX.getGroupName(),
                ConfigPropertyConstants.INTERNAL_COMPONENTS_NAMES_REGEX.getPropertyName()
        );
        if (internalNamesRegexProperty == null || StringUtils.trimToNull(internalNamesRegexProperty.getPropertyValue()) == null) {
            return false;
        }

        return Pattern.matches(StringUtils.trimToNull(internalNamesRegexProperty.getPropertyValue()), name);
    }

}
