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
package org.owasp.dependencytrack.parser.dependencycheck.util;

import org.apache.commons.lang.StringUtils;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencytrack.parser.dependencycheck.resolver.CweResolver;
import java.io.File;
import java.math.BigDecimal;

/**
 * Utility class that converts various Dependency-Check and Dependency-Track
 * models to each others format.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class ModelConverter {

    /**
     * Private constructor.
     */
    private ModelConverter() { }

    /**
     * Converts a Vulnerability (parsed by Dependency-Track) to a native Dependency-Track Vulnerability.
     * @param parserVuln the parsed Dependency-Check vulnerability to convert
     * @return a native Vulnerability object
     */
    public static org.owasp.dependencytrack.model.Vulnerability convert(
            org.owasp.dependencytrack.parser.dependencycheck.model.Vulnerability parserVuln) {

        final org.owasp.dependencytrack.model.Vulnerability persistable = new org.owasp.dependencytrack.model.Vulnerability();
        persistable.setSource(parserVuln.getSource());
        persistable.setVulnId(parserVuln.getName());

        persistable.setCwe(new CweResolver().resolve(parserVuln.getCwe()));
        persistable.setDescription(parserVuln.getDescription());

        try {
            persistable.setCvssV2BaseScore(new BigDecimal(parserVuln.getCvssScore()));
        } catch (NumberFormatException e) {
            // throw it away
        }
        return persistable;
    }

    /**
     * Converts a Dependency-Check Dependency object to a Dependency-Track Component object.
     * @param component the Component to convert to a Dependency
     * @return a Dependency object
     */
    public static org.owasp.dependencycheck.dependency.Dependency convert(
            org.owasp.dependencytrack.model.Component component) {

        final boolean isVirtual = !(StringUtils.isNotBlank(component.getMd5()) || StringUtils.isNotBlank(component.getSha1()));
        final org.owasp.dependencycheck.dependency.Dependency dependency =
                new org.owasp.dependencycheck.dependency.Dependency(new File(FileUtils.getBitBucket()), isVirtual);
        // Sets hashes if exists
        if (StringUtils.isNotBlank(component.getMd5())) {
            dependency.setMd5sum(component.getMd5());
        }
        if (StringUtils.isNotBlank(component.getSha1())) {
            dependency.setSha1sum(component.getSha1());
        }
        // Sets licenses if exists
        if (component.getResolvedLicense() != null) {
            dependency.setLicense(component.getResolvedLicense().getName());
        } else if (component.getLicense() != null) {
            dependency.setLicense(component.getLicense());
        }
        // Set the filepath of the dependency to the UUID of the component.
        // This will be used later when processing the report.
        dependency.setFileName(String.valueOf(component.getName()));
        dependency.setFilePath(String.valueOf(component.getUuid()));
        // Add evidence to the dependency
        if (component.getGroup() != null) {
            dependency.getVendorEvidence().addEvidence("dependency-track", "vendor", component.getGroup(), Confidence.HIGHEST);
        }
        if (component.getName() != null) {
            dependency.getProductEvidence().addEvidence("dependency-track", "name", component.getName(), Confidence.HIGHEST);
        }
        if (component.getVersion() != null) {
            dependency.getVersionEvidence().addEvidence("dependency-track", "version", component.getVersion(), Confidence.HIGHEST);
        }
        return dependency;
    }

}
