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
package org.dependencytrack.parser.dependencycheck.util;

import alpine.logging.Logger;
import org.apache.commons.lang.StringUtils;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.FileUtils;
import org.dependencytrack.parser.dependencycheck.resolver.CweResolver;
import org.dependencytrack.persistence.QueryManager;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.CpeParsingException;
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

    private static final Logger LOGGER = Logger.getLogger(ModelConverter.class);

    /**
     * Private constructor.
     */
    private ModelConverter() { }

    /**
     * Converts a Vulnerability (parsed by Dependency-Track) to a native Dependency-Track Vulnerability.
     * @param parserVuln the parsed Dependency-Check vulnerability to convert
     * @return a native Vulnerability object
     */
    public static org.dependencytrack.model.Vulnerability convert(QueryManager qm,
                                                                  org.dependencytrack.parser.dependencycheck.model.Vulnerability parserVuln) {

        final org.dependencytrack.model.Vulnerability persistable = new org.dependencytrack.model.Vulnerability();
        persistable.setSource(parserVuln.getSource());
        persistable.setVulnId(parserVuln.getName());

        persistable.setCwe(new CweResolver(qm).resolve(parserVuln.getCwe()));
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
            org.dependencytrack.model.Component component) {

        final boolean isVirtual = !(StringUtils.isNotBlank(component.getMd5()) || StringUtils.isNotBlank(component.getSha1()));
        final org.owasp.dependencycheck.dependency.Dependency dependency =
                new org.owasp.dependencycheck.dependency.Dependency(new File(FileUtils.getBitBucket()), isVirtual);

        dependency.setMd5sum(StringUtils.trimToNull(component.getMd5()));
        dependency.setSha1sum(StringUtils.trimToNull(component.getSha1()));
        dependency.setName(StringUtils.trimToNull(component.getName()));
        dependency.setVersion(StringUtils.trimToNull(component.getVersion()));
        dependency.setDescription(StringUtils.trimToNull(component.getDescription()));

        // Sets licenses if exists
        if (component.getResolvedLicense() != null) {
            dependency.setLicense(component.getResolvedLicense().getName());
        } else if (component.getLicense() != null) {
            dependency.setLicense(StringUtils.trimToNull(component.getLicense()));
        }
        // Set the filepath of the dependency to include the UUID of the component.
        // This will be used later when processing the report.
        String fileName = (component.getFilename() != null) ? component.getFilename() : component.getName();
        dependency.setFileName(StringUtils.trimToNull(fileName));
        dependency.setFilePath(component.getUuid() + File.separator + fileName);

        // Add evidence to the dependency
        String group = null, name = null, version = null;
        boolean isCpeUsed = false;
        if (component.getCpe() != null) {
            try {
                final Cpe cpe = CpeParser.parse(component.getCpe());
                group = cpe.getVendor();
                name = cpe.getProduct();
                version = cpe.getVersion();
                isCpeUsed = true;
            } catch (CpeParsingException e) {
                LOGGER.error("An error occurred while parsing CPE: " + component.getCpe(), e);
            }
        }
        if (!isCpeUsed) {
            if (component.getPurl() != null) {
                group = component.getPurl().getNamespace();
                name = component.getPurl().getName();
                version = component.getPurl().getVersion();
            } else {
                group = StringUtils.trimToNull(component.getGroup());
                name = StringUtils.trimToNull(component.getName());
                version = StringUtils.trimToNull(component.getVersion());
            }
        }

        if (group != null) {
            dependency.addEvidence(EvidenceType.VENDOR, "dependency-track", "vendor", group, Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.VENDOR, "dependency-track", "groupid", group, Confidence.HIGHEST);
        }
        if (name != null) {
            dependency.addEvidence(EvidenceType.PRODUCT, "dependency-track", "name", name, Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.PRODUCT, "dependency-track", "artifactid", name, Confidence.HIGHEST);
        }
        if (version != null) {
            dependency.addEvidence(EvidenceType.VERSION, "dependency-track", "version", version, Confidence.HIGHEST);
        }
        // Force 'maven' identifier so that base suppressions (included with Dependency-Check) with gav regex can be interpreted.
        // Other identifiers may also need to be put into place in the future including 'npm' and 'bintray'.
        if (group != null && name != null && version != null) {
            dependency.addIdentifier("maven", group + ":" + name + ":" + version, null, Confidence.HIGHEST);
        }
        return dependency;
    }

}
