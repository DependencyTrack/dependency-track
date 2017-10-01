/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
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

    /**
     * Resolves a CWE by its string representation.
     * @param cweString the string to resolve
     */
    public Cwe resolve(String cweString) {
        try (QueryManager qm = new QueryManager()) {
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
        }
        return null;
    }
}
