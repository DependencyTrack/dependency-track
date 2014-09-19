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
package org.owasp.dependencytrack.tasks.dependencycheck;

import org.apache.commons.digester.Digester;
import org.hibernate.Query;
import org.hibernate.SessionFactory;
import org.hibernate.classic.Session;
import org.owasp.dependencycheck.agent.DependencyCheckScanAgent;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.exception.ScanAgentException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencytrack.Constants;
import org.owasp.dependencytrack.model.Library;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.ScanResults;
import org.owasp.dependencytrack.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class DependencyCheckAnalysis {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DependencyCheckAnalysis.class);

    SessionFactory sessionFactory;

    public DependencyCheckAnalysis(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public synchronized void execute() {
        if (performAnalysis()) {
            try {
                Analysis analysis = analyzeResults();
                commitVulnerabilityData(analysis);
            } catch (SAXException | IOException e) {
                LOGGER.error("An error occurred while analyzing Dependency-Check results: " + e.getMessage());
            }
        }
    }

    public synchronized boolean performAnalysis() {
        LOGGER.info("Executing Dependency-Check Task");
        sessionFactory.openSession();

        // Retrieve a list of all library versions defined in the system
        Query query = sessionFactory.getCurrentSession().createQuery("from LibraryVersion");
        @SuppressWarnings("unchecked")
        List<LibraryVersion> libraries = query.list();

        // iterate through the libraries, create evidence and create the resulting dependency
        List<Dependency> dependencies = new ArrayList<>();
        for (LibraryVersion libraryVersion: libraries) {
            Library library = libraryVersion.getLibrary();
            final Dependency dependency = new Dependency(new File(FileUtils.getBitBucket()));
            dependency.setMd5sum(UUID.randomUUID().toString().replace("-",""));
            dependency.setSha1sum(UUID.randomUUID().toString().replace("-", ""));
            dependency.setLicense(library.getLicense().getLicensename());
            dependency.setDescription(String.valueOf(libraryVersion.getId()));
            dependency.getVendorEvidence().addEvidence("dependency-track", "vendor", library.getLibraryVendor().getVendor(), Confidence.HIGHEST);
            dependency.getProductEvidence().addEvidence("dependency-track", "name", library.getLibraryname(), Confidence.HIGHEST);
            dependency.getVersionEvidence().addEvidence("dependency-track", "version", libraryVersion.getLibraryversion(), Confidence.HIGHEST);
            dependencies.add(dependency);
        }

        LOGGER.info("Performing Dependency-Check analysis against " + dependencies.size() + " component(s)");

        final DependencyCheckScanAgent scanAgent = new DependencyCheckScanAgent();
        scanAgent.setConnectionString("jdbc:h2:file:%s;FILE_LOCK=SERIALIZED;AUTOCOMMIT=ON;");
        scanAgent.setDataDirectory(Constants.DATA_DIR);
        scanAgent.setReportOutputDirectory(Constants.APP_DIR);
        scanAgent.setReportFormat(ReportGenerator.Format.XML);
        scanAgent.setAutoUpdate(true);
        scanAgent.setDependencies(dependencies);

        boolean success = false;
        try {
            scanAgent.execute();
            success = true;
        } catch (ScanAgentException e) {
            LOGGER.error("An error occurred executing Dependency-Check scan agent: " + e.getMessage());
        }

        if (!sessionFactory.isClosed()) {
            sessionFactory.close();
        }
        LOGGER.info("Dependency-Check analysis complete");
        return success;
    }

    public synchronized Analysis analyzeResults() throws SAXException, IOException {
        Digester digester = new Digester();
        digester.setValidating(false);
        digester.setClassLoader(DependencyCheckAnalysis.class.getClassLoader());

        digester.addObjectCreate("analysis", Analysis.class);

        String depXpath = "analysis/dependencies/dependency";
        digester.addObjectCreate(depXpath, Dependency.class);
        digester.addBeanPropertySetter(depXpath + "/fileName");
        digester.addBeanPropertySetter(depXpath + "/filePath");
        digester.addBeanPropertySetter(depXpath + "/md5", "md5sum");
        digester.addBeanPropertySetter(depXpath + "/sha1", "sha1sum");
        digester.addBeanPropertySetter(depXpath + "/description");
        digester.addBeanPropertySetter(depXpath + "/license");

        String vulnXpath = "analysis/dependencies/dependency/vulnerabilities/vulnerability";
        digester.addObjectCreate(vulnXpath, org.owasp.dependencycheck.dependency.Vulnerability.class);
        digester.addBeanPropertySetter(vulnXpath + "/name");
        digester.addBeanPropertySetter(vulnXpath + "/cvssScore");
        digester.addBeanPropertySetter(vulnXpath + "/cwe");
        digester.addBeanPropertySetter(vulnXpath + "/description");

        String refXpath = "analysis/dependencies/dependency/vulnerabilities/vulnerability/references/reference";
        digester.addObjectCreate(refXpath, Reference.class);
        digester.addBeanPropertySetter(refXpath + "/source");
        digester.addBeanPropertySetter(refXpath + "/url");
        digester.addBeanPropertySetter(refXpath + "/name");

        digester.addSetNext(refXpath, "addReference");
        digester.addSetNext(vulnXpath, "addVulnerability");
        digester.addSetNext(depXpath, "addDependency");

        Analysis module = (Analysis) digester.parse(new File(Constants.APP_DIR + File.separator + "dependency-check-report.xml"));
        if (module == null) {
            throw new SAXException("Input stream is not a Dependency-Check report file.");
        }
        return module;
    }

    public void commitVulnerabilityData(Analysis analysis) {
        LOGGER.info("Committing vulnerability analysis");
        for (Dependency dependency: analysis.getDependencies()) {

            if (dependency.getVulnerabilities().size() == 0) {
                // No vulnerabilities found for this dependency - moving along...
                break;
            }

            // The primary key for the library version is stored in the description field for reference
            Session session = sessionFactory.openSession();
            final Query query = session.createQuery("FROM LibraryVersion WHERE id=:id");
            query.setParameter("id", new Integer(dependency.getDescription()));
            LibraryVersion libraryVersion = (LibraryVersion)query.list().get(0);

            session.beginTransaction();

            ScanResults scan = new ScanResults();
            scan.setScanDate(new Date());
            scan.setUUID(UUID.randomUUID().toString());
            scan.setLibraryVersion(libraryVersion);

            session.save(scan);

            // Iterate through native Dependency-Check Vulnerability objects and create Dependency-Track Vulnerability objects
            for (org.owasp.dependencycheck.dependency.Vulnerability dcVuln: dependency.getVulnerabilities()) {
                Vulnerability vuln = new Vulnerability();
                vuln.setCwe(dcVuln.getCwe());
                vuln.setCve(dcVuln.getName());
                vuln.setCvss(dcVuln.getCvssScore());
                vuln.setDescription(dcVuln.getDescription());
                vuln.setScanResults(scan);
                LOGGER.debug("Recording vulnerability: " + dcVuln.getName() + " against " + libraryVersion.getLibrary().getLibraryname() + " " + libraryVersion.getLibraryversion());
                session.save(vuln);
            }
            session.getTransaction().commit();
            session.close();
        }
    }

}
