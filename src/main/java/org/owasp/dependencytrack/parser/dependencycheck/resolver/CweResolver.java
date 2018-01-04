/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.parser.dependencycheck.resolver;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencytrack.model.Cwe;
import org.owasp.dependencytrack.persistence.QueryManager;

/**
 * Attempts to resolve an existing Dependency-Track CWE from a
 * Dependency-Check Vulnerability.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class CweResolver {

    private QueryManager qm;

    public CweResolver(QueryManager qm) {
        this.qm = qm;
    }

    /**
     * Resolves a CWE by its string representation.
     * @param cweString the string to resolve
     */
    public Cwe resolve(String cweString) {
        if (StringUtils.isNotBlank(cweString)) {
            String lookupString = "";
            if (cweString.startsWith("CWE-") && cweString.contains(" ")) {
                // This is likely to be in the following format:
                // CWE-264 Permissions, Privileges, and Access Controls
                lookupString = cweString.substring(4, cweString.indexOf(" "));
            } else if (cweString.startsWith("CWE-") && cweString.length() < 9) {
                // This is likely to be in the following format:
                // CWE-264
                lookupString = cweString.substring(4, cweString.length());
            } else if (cweString.length() < 5) {
                // This is likely to be in the following format:
                // 264
                lookupString = cweString;
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
