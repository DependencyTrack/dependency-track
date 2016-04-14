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
package org.owasp.dependencytrack.tasks.dependencycheck;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.codehaus.staxmate.SMInputFactory;
import org.codehaus.staxmate.in.SMHierarchicCursor;
import org.codehaus.staxmate.in.SMInputCursor;
import org.hibernate.Query;
import org.hibernate.Session;
import org.owasp.dependencycheck.agent.DependencyCheckScanAgent;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.ScanAgentException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencytrack.dao.BaseDao;
import org.owasp.dependencytrack.model.Library;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.ScanResult;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.service.VulnerabilityService;
import org.owasp.dependencytrack.tasks.DependencyCheckAnalysisRequestEvent;
import org.owasp.dependencytrack.util.XmlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;


/**
 * Performs a Dependency-Check analysis.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Service
public class DependencyCheckAnalysis extends BaseDao implements ApplicationListener<DependencyCheckAnalysisRequestEvent> {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DependencyCheckAnalysis.class);

    @Value("${app.data.dir}")
    private String appDataDir;

    @Value("${app.dir}")
    private String appDir;

    @Value("${app.suppression.path}")
    private String appSuppressionPath;

    @Autowired
    private VulnerabilityService vulnerabilityService;

    private Session session;

    private AtomicBoolean inProgress = new AtomicBoolean(false);

    public DependencyCheckAnalysis() {
    }

    /**
     * {@inheritDoc}
     */
    public void onApplicationEvent(DependencyCheckAnalysisRequestEvent event) {
        if(!inProgress.get()) {
            try {
                inProgress.set(true);
                LOGGER.info("Starting Dependency-Check analysis");
                this.session = getSession();
                final List<LibraryVersion> libraryVersions = event.getLibraryVersions();
                if (libraryVersions == null || libraryVersions.size() == 0) {
                    execute();
                } else {
                    execute(libraryVersions);
                }
                vulnerabilityService.updateLibraryVersionVulnerabilityCount();
                vulnerabilityService.updateApplicationVersionVulnerabilityCount();
                cleanup();
            } finally {
                inProgress.set(false);
            }
        }
    }

    /**
     * Performs a scan against all libraries in the database.
     */
    @Transactional
    public synchronized void execute() {
        // Retrieve a list of all library versions defined in the system
        final Query query = session.createQuery("from LibraryVersion");
        @SuppressWarnings("unchecked")
        final List<LibraryVersion> libraryVersions = query.list();

        execute(libraryVersions);
    }

    /**
     * Performs a scan against the specified list of libraries.
     * @param libraryVersions a list of LibraryVersion object to perform a scan against
     */
    public synchronized void execute(List<LibraryVersion> libraryVersions) {
        if (performAnalysis(libraryVersions)) {
            try {
                analyzeResults();
            } catch (SAXException | IOException e) {
                LOGGER.error("An error occurred while analyzing Dependency-Check results: " + e.getMessage());
            }
        }
    }

    /**
     * Performs a Dependency-Check analysis against the specified list of libraries.
     * @param libraryVersions a list of LibraryVersion object to perform a scan against
     * @return true if scan was successful, false if scan failed for some reason
     */
    private synchronized boolean performAnalysis(List<LibraryVersion> libraryVersions) {
        LOGGER.info("Executing Dependency-Check Task");

        // iterate through the libraries, create evidence and create the resulting dependency
        final List<Dependency> dependencies = new ArrayList<>();
        for (LibraryVersion libraryVersion: libraryVersions) {
            final Library library = libraryVersion.getLibrary();
            final Dependency dependency = new Dependency(new File(FileUtils.getBitBucket()));

            if (StringUtils.isNotBlank(libraryVersion.getMd5())) {
                dependency.setMd5sum(libraryVersion.getMd5());
            } else {
                dependency.setMd5sum(libraryVersion.getUuidAsMd5Hash());
            }

            if (StringUtils.isNotBlank(libraryVersion.getSha1())) {
                dependency.setSha1sum(libraryVersion.getSha1());
            } else {
                dependency.setSha1sum(libraryVersion.getUuidAsSha1Hash());
            }

            final License license = library.getLicense();
            if (license != null) {
                dependency.setLicense(library.getLicense().getLicensename());
            }
            dependency.setDescription(String.valueOf(libraryVersion.getId()));
            dependency.getVendorEvidence().addEvidence("dependency-track", "vendor", library.getLibraryVendor().getVendor(), Confidence.HIGHEST);
            dependency.getProductEvidence().addEvidence("dependency-track", "name", library.getLibraryname(), Confidence.HIGHEST);
            dependency.getVersionEvidence().addEvidence("dependency-track", "version", libraryVersion.getLibraryversion(), Confidence.HIGHEST);
            dependencies.add(dependency);
        }

        LOGGER.info("Performing Dependency-Check analysis against " + dependencies.size() + " component(s)");

        final DependencyCheckScanAgent scanAgent = new DependencyCheckScanAgent();
        scanAgent.setConnectionString("jdbc:h2:file:%s;FILE_LOCK=SERIALIZED;AUTOCOMMIT=ON;");
        scanAgent.setDataDirectory(appDataDir);
        scanAgent.setReportOutputDirectory(appDir);
        scanAgent.setReportFormat(ReportGenerator.Format.ALL);
        scanAgent.setAutoUpdate(true);
        scanAgent.setDependencies(dependencies);
        scanAgent.setCentralAnalyzerEnabled(false);
        scanAgent.setNexusAnalyzerEnabled(false);

        // If a global suppression file exists, use it.
        final File suppressions = new File(appSuppressionPath);
        if (suppressions.exists() && suppressions.isFile()) {
            scanAgent.setSuppressionFile(suppressions.getAbsolutePath());
        }

        boolean success = false;
        try {
            scanAgent.execute();
            success = true;
        } catch (ScanAgentException e) {
            LOGGER.error("An error occurred executing Dependency-Check scan agent: " + e.getMessage());
        }

        LOGGER.info("Dependency-Check analysis complete");
        return success;
    }

    /**
     * Analyzes the result (dependency-check-report.xml) from a Dependency-Check scan.
     * @throws SAXException if it's not able to parse the XML report
     * @throws IOException if it's not able to open the XML report
     */
    private synchronized void analyzeResults() throws SAXException, IOException {
        final SMInputFactory inputFactory = XmlUtil.newStaxParser();
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(new File(appDir + File.separator + "dependency-check-report.xml"));
            final SMHierarchicCursor rootC = inputFactory.rootElementCursor(fis);
            rootC.advance(); // <analysis>
            final SMInputCursor cursor = rootC.childCursor();
            while (cursor.getNext() != null) {
                final String nodeName = cursor.getLocalName();
                if ("dependencies".equals(nodeName)) {
                    processDependencies(cursor);
                }
            }
        } catch (XMLStreamException e) {
            throw new IllegalStateException("XML is not valid", e);
        } finally {
            IOUtils.closeQuietly(fis);
        }
    }

    /**
     * Processes a node of dependency tags.
     * @param depC a SMInputCursor cursor
     * @throws XMLStreamException if exception is thrown
     */
    private void processDependencies(SMInputCursor depC) throws XMLStreamException {
        final SMInputCursor cursor = depC.childElementCursor("dependency");
        while (cursor.getNext() != null) {
            processDependency(cursor);
        }
    }

    /**
     * Processes a single dependency node.
     * @param depC a SMInputCursor cursor
     * @throws XMLStreamException if exception is thrown
     */
    private void processDependency(SMInputCursor depC) throws XMLStreamException {
        int libraryVersionId = -1;
        List<String[]> matchedCpes = Collections.emptyList();
        final SMInputCursor childCursor = depC.childCursor();
        while (childCursor.getNext() != null) {
            final String nodeName = childCursor.getLocalName();
            if ("description".equals(nodeName)) {
                libraryVersionId = Integer.valueOf(StringUtils.trim(childCursor.collectDescendantText(false)));
            } else if ("identifiers".equals(nodeName)) {
                matchedCpes = processIdentifiers(childCursor);
            } else if ("vulnerabilities".equals(nodeName)) {
                processVulnerabilities(childCursor, libraryVersionId, matchedCpes);
            }
        }
    }

    /**
     * Processes a node of identifier tags.
     * @param identsC a SMInputCursor cursor
     * @throws XMLStreamException if exception is thrown
     */
    private List<String[]> processIdentifiers(SMInputCursor identsC) throws XMLStreamException {
        final ArrayList<String[]> identifiers = new ArrayList<>();
        final SMInputCursor cursor = identsC.childElementCursor("identifier");
        while (cursor.getNext() != null) {
            final String[] identifier = processIdentifier(cursor);
            identifiers.add(identifier);
        }
        return identifiers;
    }

    /**
     * Processes a single identifier node.
     * @param identC a SMInputCursor cursor
     * @throws XMLStreamException if exception is thrown
     */
    private String[] processIdentifier(SMInputCursor identC) throws XMLStreamException {
        final String[] values = new String[2];
        final SMInputCursor childCursor = identC.childCursor();
        while (childCursor.getNext() != null) {
            final String nodeName = childCursor.getLocalName();
            if ("name".equals(nodeName)) {
                String value = StringUtils.trim(childCursor.collectDescendantText(false));
                if (value != null && value.startsWith("(") && value.endsWith(")")) {
                    value = value.substring(1, value.length() - 1);
                }
                values[0] = value;
            } else if ("url".equals(nodeName)) {
                values[1] = StringUtils.trim(childCursor.collectDescendantText(false));
            }
        }
        return values;
    }

    /**
     * Processes a node vulnerability tags.
     * @param vulnC a SMInputCursor cursor
     * @param libraryVersionId the library version identifier associated with this collection of vulnerabilities
     * @param matchedCpes a list of CPEs that the dependency was matched against
     * @throws XMLStreamException if exception is thrown
     */
    private void processVulnerabilities(SMInputCursor vulnC, int libraryVersionId, List<String[]> matchedCpes) throws XMLStreamException {
        final SMInputCursor cursor = vulnC.childElementCursor("vulnerability");
        while (cursor.getNext() != null) {
            processVulnerability(cursor, libraryVersionId, matchedCpes);
        }
    }

    /**
     * Processes a single dependency node.
     * @param vulnC a SMInputCursor cursor
     * @param libraryVersionId the library version identifier associated with this vulnerability
     * @param matchedCpes a list of CPEs that the dependency was matched against
     * @throws XMLStreamException if exception is thrown
     */
    private void processVulnerability(SMInputCursor vulnC, int libraryVersionId, List<String[]> matchedCpes) throws XMLStreamException {
        String name = null, cvssScore = null, cwe = null, description = null;
        final SMInputCursor childCursor = vulnC.childCursor();
        while (childCursor.getNext() != null) {
            final String nodeName = childCursor.getLocalName();
            if ("name".equals(nodeName)) {
                name = StringUtils.trim(childCursor.collectDescendantText(false));
            } else if ("cvssScore".equals(nodeName)) {
                cvssScore = StringUtils.trim(childCursor.collectDescendantText(false));
            } else if ("cwe".equals(nodeName)) {
                cwe = StringUtils.trim(childCursor.collectDescendantText(false));
            } else if ("description".equals(nodeName)) {
                description = StringUtils.trim(childCursor.collectDescendantText(false));
            }
        }
        final Vulnerability vulnerability = getVulnerability(name);
        vulnerability.setName(name);
        vulnerability.setCvssScore(new BigDecimal(cvssScore));
        vulnerability.setCwe(cwe);
        vulnerability.setDescription(description);
        if (matchedCpes.size() > 0) {
            vulnerability.setMatchedCPE(matchedCpes.get(0)[0]);
        }
        commitVulnerabilityData(vulnerability, libraryVersionId);
    }


    /**
     * Given an Analysis object (a result from a Dependency-Check scan), this method
     * will commit the results of the scan to the database.
     * @param vulnerability the newly created vulnerability to commit
     * @param libraryVersionId the unique identifier of the library version associated with the vulnerability
     */
    @Transactional
    private void commitVulnerabilityData(final Vulnerability vulnerability, final int libraryVersionId) {
        final Query query = session.createQuery("FROM LibraryVersion WHERE id=:id");
        query.setParameter("id", libraryVersionId);
        final LibraryVersion libraryVersion = (LibraryVersion) query.uniqueResult();

        if (libraryVersion == null) {
            return;
        }

        // Check if it's an existing vulnerability
        if (vulnerability.getId() != null) {
            final Query scanQuery = session.createQuery("from ScanResult s where s.vulnerability=:vulnerability and s.scanDate=:scanDate and s.libraryVersion=:libraryVersion");
            scanQuery.setParameter("vulnerability", vulnerability);
            scanQuery.setParameter("scanDate", new Date());
            scanQuery.setParameter("libraryVersion", libraryVersion);
            if (scanQuery.list().size() > 0) {
                return; // Don't add the same entry more than once
            }
        }

        session.save(vulnerability);
        final ScanResult scan = new ScanResult();
        scan.setScanDate(new Date());
        scan.setLibraryVersion(libraryVersion);
        scan.setVulnerability(vulnerability);
        session.save(scan);
    }

    /**
     * Queries the database for a given CVE
     * @param name the name of the vulnerability (typically a CVE identifier)
     * @return a Vulnerability object
     */
    private Vulnerability getVulnerability(final String name) {
        final Query query = session.createQuery("from Vulnerability where name=:name order by id asc");
        query.setParameter("name", name);
        @SuppressWarnings("unchecked")
        final List<Vulnerability> vulns = query.list();
        if (vulns.size() > 0) {
            return vulns.get(0);
        }
        return new Vulnerability();
    }

}
