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
package org.dependencytrack.parser.common.resolver;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.persistence.QueryManager;

/**
 * Attempts to resolve an internal CWE object from a string
 * representation of a CWE.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class CweResolver {

    private final QueryManager qm;

    public CweResolver(final QueryManager qm) {
        this.qm = qm;
    }

    /**
     * Resolves a CWE by its string representation.
     * @param cweString the string to resolve
     */
    public Cwe resolve(final String cweString) {
        if (StringUtils.isNotBlank(cweString)) {
            final String string = cweString.trim();
            String lookupString = "";
            if (string.startsWith("CWE-") && string.contains(" ")) {
                // This is likely to be in the following format:
                // CWE-264 Permissions, Privileges, and Access Controls
                lookupString = string.substring(4, string.indexOf(" "));
            } else if (string.startsWith("CWE-") && string.length() < 9) {
                // This is likely to be in the following format:
                // CWE-264
                lookupString = string.substring(4, string.length());
            } else if (string.length() < 5) {
                // This is likely to be in the following format:
                // 264
                lookupString = string;
            }

            try {
                return qm.getCweById(Integer.valueOf(lookupString));
            } catch (NumberFormatException e) {
                // throw it away
            }
        }
        return null;
    }
}
