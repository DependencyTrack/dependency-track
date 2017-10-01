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
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.parser.dependencycheck.model.Dependency;
import org.owasp.dependencytrack.persistence.QueryManager;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Attempts to resolve an existing Dependency-Track License from a
 * Dependency-Check Dependency.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class LicenseResolver implements IResolver {

    /**
     * The hinter provides manual assistance for mapping license text to
     * a specific SPDX license ID.
     */
    private static final Map<String, String> HINTS = new HashMap<>();
    static {
        HINTS.put("GNU GENERAL PUBLIC LICENSE version 2 or higher", "GPL-2.0+");
        HINTS.put("CDDLv1.0", "CDDL-1.0");
        HINTS.put("CDDL+GPL", "CDDL-1.0");
        HINTS.put("CDDL+GPL_1_1", "CDDL-1.1");
        HINTS.put("GPLv2 with classpath exception", "GPL-2.0-with-classpath-exception");
    }

    /**
     * {@inheritDoc}
     */
    public License resolve(Dependency dependency) {
        if (dependency.getLicense() != null) {
            try (QueryManager qm = new QueryManager()) {
                final List<License> licenses = qm.getLicenses().getList(License.class);
                for (License license : licenses) {
                    if (StringUtils.containsIgnoreCase(dependency.getLicense(), license.getLicenseId())) {
                        return license;
                    } else if (StringUtils.containsIgnoreCase(dependency.getLicense(), license.getName())) {
                        return license;
                    } else if (license.getSeeAlso() != null && license.getSeeAlso().length > 0) {
                        for (String seeAlso : license.getSeeAlso()) {

                            // Remove protocol from being evaluated
                            seeAlso = seeAlso.replaceFirst("http://", "").replaceFirst("https://", "");

                            // Trim because the data may contain empty strings
                            if (StringUtils.trimToNull(seeAlso) != null) {
                                if (dependency.getLicense().contains(seeAlso)) {
                                    return license;
                                }
                            }

                            // No match yet - try using hints
                            for (Map.Entry<String, String> entry : HINTS.entrySet()) {
                                if (StringUtils.containsIgnoreCase(seeAlso, entry.getKey())) {
                                    // Match was found. Retrieve the license from the SPDX license ID
                                    return qm.getLicense(entry.getValue());
                                }
                            }

                        }
                    }
                }
            }
        }
        return null;
    }

}
