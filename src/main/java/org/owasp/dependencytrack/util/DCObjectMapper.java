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
 *
 * Copyright (c) Axway. All Rights Reserved.
 */

package org.owasp.dependencytrack.util;

import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencytrack.model.Library;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.Vulnerability;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;

public class DCObjectMapper {


    public static Dependency toDCDependency(LibraryVersion libraryVersion, List<Vulnerability> vulnerabilities) {
        final Library library = libraryVersion.getLibrary();
        final Dependency dependency = new Dependency(new File(FileUtils.getBitBucket()));
        dependency.setFileName(library.getLibraryVendor().getVendor() + " " + library.getLibraryname() + " " + libraryVersion.getLibraryversion());
        dependency.setMd5sum((libraryVersion.getMd5() != null) ? libraryVersion.getMd5() : libraryVersion.getUndashedUuid());
        dependency.setSha1sum((libraryVersion.getSha1() != null) ? libraryVersion.getSha1() : libraryVersion.getUndashedUuid());
        dependency.setLicense(library.getLicense().getLicensename());
        dependency.setDescription(String.valueOf(libraryVersion.getId()));
        dependency.getVendorEvidence().addEvidence("dependency-track", "vendor", library.getLibraryVendor().getVendor(), Confidence.HIGHEST);
        dependency.getProductEvidence().addEvidence("dependency-track", "name", library.getLibraryname(), Confidence.HIGHEST);
        dependency.getVersionEvidence().addEvidence("dependency-track", "version", libraryVersion.getLibraryversion(), Confidence.HIGHEST);

        for (Vulnerability vulnerability: vulnerabilities) {
            dependency.addVulnerability(toDCVulnerability(vulnerability));
            try {
                dependency.addIdentifier("cpe", vulnerability.getMatchedCPE(), "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on&cpe_version=" + URLEncoder.encode(vulnerability.getMatchedCPE(), "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                dependency.addIdentifier("cpe", vulnerability.getMatchedCPE(), "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on&cpe_version=" + URLEncoder.encode(vulnerability.getMatchedCPE()));
            }
        }
        return dependency;
    }

    public static org.owasp.dependencycheck.dependency.Vulnerability toDCVulnerability(Vulnerability vulnerability) {
        org.owasp.dependencycheck.dependency.Vulnerability dcvuln = new org.owasp.dependencycheck.dependency.Vulnerability();
        dcvuln.setName(vulnerability.getName());
        dcvuln.setDescription(vulnerability.getDescription());
        dcvuln.setCvssScore(vulnerability.getCvssScore());
        dcvuln.setCwe(vulnerability.getCwe());
        dcvuln.setMatchedCPE(vulnerability.getMatchedCPE(), vulnerability.getMatchedAllPreviousCPE());
        //todo: add this in when DC XML supports it
        //dcvuln.setCvssAccessComplexity(vulnerability.getCvssAccessComplexity());
        //dcvuln.setCvssAccessVector(vulnerability.getCvssAccessVector());
        //dcvuln.setCvssAuthentication(vulnerability.getCvssAuthentication());
        //dcvuln.setCvssAvailabilityImpact(vulnerability.getCvssAvailabilityImpact());
        //dcvuln.setCvssConfidentialityImpact(vulnerability.getCvssConfidentialityImpact());
        //dcvuln.setCvssIntegrityImpact(vulnerability.getCvssIntegrityImpact());
        return dcvuln;
    }

    public static Vulnerability toDTVulnerability(Vulnerability dtvuln,
                                                  org.owasp.dependencycheck.dependency.Dependency dependency,
                                                  org.owasp.dependencycheck.dependency.Vulnerability vulnerability) {
        dtvuln.setName(vulnerability.getName());
        dtvuln.setDescription(vulnerability.getDescription());
        dtvuln.setCvssScore(vulnerability.getCvssScore());

        for (Identifier identifier: dependency.getIdentifiers()) {
            dtvuln.setMatchedCPE(identifier.getValue().replace("(", "").replace(")", ""));
            break;
        }

        dtvuln.setCwe(vulnerability.getCwe());
        //todo: add this in when DC XML supports it
        //dtvuln.setCvssAccessComplexity(vulnerability.getCvssAccessComplexity());
        //dtvuln.setCvssAccessVector(vulnerability.getCvssAccessVector());
        //dtvuln.setCvssAuthentication(vulnerability.getCvssAuthentication());
        //dtvuln.setCvssAvailabilityImpact(vulnerability.getCvssAvailabilityImpact());
        //dtvuln.setCvssConfidentialityImpact(vulnerability.getCvssConfidentialityImpact());
        //dtvuln.setCvssIntegrityImpact(vulnerability.getCvssIntegrityImpact());
        return dtvuln;
    }

}
