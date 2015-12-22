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
package org.owasp.dependencytrack.util;

import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencytrack.model.Library;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Vulnerability;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;

/**
 * Utility class that maps Dependency-Check to and from Dependency-Track objects.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public final class DCObjectMapper {

    /**
     * Private constructor.
     */
    private DCObjectMapper() { }

    /**
     * Converts a Dependency-Track dependency (LibraryVersion + Vulnerabilities) into a
     * Dependency-Check Dependency object.
     * @param libraryVersion a Dependency-Track LibraryVersion object
     * @param vulnerabilities a list of Dependency-Track Vulnerability objects
     * @return a Dependency-Check Dependency object
     */
    public static Dependency toDCDependency(LibraryVersion libraryVersion, List<Vulnerability> vulnerabilities) {
        final Library library = libraryVersion.getLibrary();
        final Dependency dependency = new Dependency(new File(FileUtils.getBitBucket()));
        dependency.setFileName(library.getLibraryVendor().getVendor() + " " + library.getLibraryname() + " " + libraryVersion.getLibraryversion());
        dependency.setMd5sum((libraryVersion.getMd5() != null) ? libraryVersion.getMd5() : libraryVersion.getUuidAsMd5Hash());
        dependency.setSha1sum((libraryVersion.getSha1() != null) ? libraryVersion.getSha1() : libraryVersion.getUuidAsSha1Hash());
        final License license = library.getLicense();
        if (license != null) {
            dependency.setLicense(library.getLicense().getLicensename());
        }
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

    /**
     * Converts a Dependency-Track Vulnerability object to a Dependency-Check Vulnerability object.
     * @param vulnerability a Dependency-Track Vulnerability object
     * @return a Dependency-Check Vulnerability object
     */
    public static org.owasp.dependencycheck.dependency.Vulnerability toDCVulnerability(Vulnerability vulnerability) {
        final org.owasp.dependencycheck.dependency.Vulnerability dcvuln = new org.owasp.dependencycheck.dependency.Vulnerability();
        dcvuln.setName(vulnerability.getName());
        dcvuln.setDescription(vulnerability.getDescription());
        dcvuln.setCvssScore(vulnerability.getCvssScore().floatValue());
        dcvuln.setCwe(vulnerability.getCwe());
        dcvuln.setMatchedCPE(vulnerability.getMatchedCPE(), vulnerability.getMatchedAllPreviousCPE());
        return dcvuln;
    }

}
