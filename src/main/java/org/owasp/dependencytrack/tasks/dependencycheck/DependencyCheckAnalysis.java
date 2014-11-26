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
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencytrack.Constants;
import org.owasp.dependencytrack.model.Library;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.ScanResult;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.tasks.DependencyCheckAnalysisRequestEvent;
import org.owasp.dependencytrack.util.DCObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Service;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.util.*;

@Service
public class DependencyCheckAnalysis implements ApplicationListener<DependencyCheckAnalysisRequestEvent> {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DependencyCheckAnalysis.class);

    @Autowired
    private SessionFactory sessionFactory;

    public DependencyCheckAnalysis() {
    }

    public DependencyCheckAnalysis(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @Override
    public void onApplicationEvent(DependencyCheckAnalysisRequestEvent event) {
        List<LibraryVersion> libraryVersions = event.getLibraryVersions();
        execute(libraryVersions);
    }

    public synchronized void execute() {
        // Retrieve a list of all library versions defined in the system
        final Query query = sessionFactory.getCurrentSession().createQuery("from LibraryVersion");
        @SuppressWarnings("unchecked")
        final List<LibraryVersion> libraryVersions = query.list();

        performAnalysis(libraryVersions);
    }

    public synchronized void execute(List<LibraryVersion> libraryVersions) {
        if (performAnalysis(libraryVersions)) {
            try {
                final Analysis analysis = analyzeResults();
                commitVulnerabilityData(analysis);
            } catch (SAXException | IOException e) {
                LOGGER.error("An error occurred while analyzing Dependency-Check results: " + e.getMessage());
            }
        }
    }

    private synchronized boolean performAnalysis(List<LibraryVersion> libraryVersions) {
        LOGGER.info("Executing Dependency-Check Task");
        sessionFactory.openSession();

        // iterate through the libraries, create evidence and create the resulting dependency
        final List<Dependency> dependencies = new ArrayList<>();
        for (LibraryVersion libraryVersion: libraryVersions) {
            final Library library = libraryVersion.getLibrary();
            final Dependency dependency = new Dependency(new File(FileUtils.getBitBucket()));
            dependency.setMd5sum(UUID.randomUUID().toString().replace("-", ""));
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
        scanAgent.setCentralAnalyzerEnabled(false);
        scanAgent.setNexusAnalyzerEnabled(false);

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

    private synchronized Analysis analyzeResults() throws SAXException, IOException {
        final Digester digester = new Digester();
        digester.setValidating(false);
        digester.setClassLoader(DependencyCheckAnalysis.class.getClassLoader());

        digester.addObjectCreate("analysis", Analysis.class);

        final String depXpath = "analysis/dependencies/dependency";
        digester.addObjectCreate(depXpath, Dependency.class);
        digester.addBeanPropertySetter(depXpath + "/fileName");
        digester.addBeanPropertySetter(depXpath + "/filePath");
        digester.addBeanPropertySetter(depXpath + "/md5", "md5sum");
        digester.addBeanPropertySetter(depXpath + "/sha1", "sha1sum");
        digester.addBeanPropertySetter(depXpath + "/description");
        digester.addBeanPropertySetter(depXpath + "/license");

        final String identXpath = "analysis/dependencies/dependency/identifiers/identifier";
        digester.addObjectCreate(identXpath, org.owasp.dependencycheck.dependency.Identifier.class);
        digester.addBeanPropertySetter(identXpath + "/name", "value");
        digester.addBeanPropertySetter(identXpath + "/url");

        final String vulnXpath = "analysis/dependencies/dependency/vulnerabilities/vulnerability";
        digester.addObjectCreate(vulnXpath, org.owasp.dependencycheck.dependency.Vulnerability.class);
        digester.addBeanPropertySetter(vulnXpath + "/name");
        digester.addBeanPropertySetter(vulnXpath + "/cvssScore");
        digester.addBeanPropertySetter(vulnXpath + "/cwe");
        digester.addBeanPropertySetter(vulnXpath + "/description");

        final String refXpath = "analysis/dependencies/dependency/vulnerabilities/vulnerability/references/reference";
        digester.addObjectCreate(refXpath, Reference.class);
        digester.addBeanPropertySetter(refXpath + "/source");
        digester.addBeanPropertySetter(refXpath + "/url");
        digester.addBeanPropertySetter(refXpath + "/name");

        digester.addSetNext(refXpath, "addReference");
        digester.addSetNext(identXpath, "addIdentifier");
        digester.addSetNext(vulnXpath, "addVulnerability");
        digester.addSetNext(depXpath, "addDependency");

        final Analysis module = (Analysis) digester.parse(new File(Constants.APP_DIR + File.separator + "dependency-check-report.xml"));
        if (module == null) {
            throw new SAXException("Input stream is not a Dependency-Check report file.");
        }
        return module;
    }

    private void commitVulnerabilityData(Analysis analysis) {
        LOGGER.info("Committing vulnerability analysis");
        for (Dependency dependency: analysis.getDependencies()) {

            if (dependency.getVulnerabilities().size() == 0) {
                // No vulnerabilities found for this dependency - moving along...
                break;
            }

            // The primary key for the library version is stored in the description field for reference
            final Session session = sessionFactory.openSession();
            final Query query = session.createQuery("FROM LibraryVersion WHERE id=:id");
            query.setParameter("id", new Integer(dependency.getDescription()));
            final LibraryVersion libraryVersion = (LibraryVersion) query.list().get(0);

            session.beginTransaction();

            // Iterate through native Dependency-Check Vulnerability objects and create Dependency-Track Vulnerability objects
            for (org.owasp.dependencycheck.dependency.Vulnerability dcVuln: dependency.getVulnerabilities()) {
                final Vulnerability vuln = getVulnerability(dcVuln.getName(), session);
                DCObjectMapper.toDTVulnerability(vuln, dependency, dcVuln);

                if (vuln.getId() == null || vuln.getId() == 0) {
                    LOGGER.debug("Recording vulnerability: " + dcVuln.getName() + " against " + libraryVersion.getLibrary().getLibraryname() + " " + libraryVersion.getLibraryversion());
                    session.save(vuln);
                } else {
                    LOGGER.debug("Updating vulnerability: " + dcVuln.getName());
                    session.update(vuln);
                }

                final ScanResult scan = new ScanResult();
                scan.setScanDate(new Date());
                scan.setLibraryVersion(libraryVersion);
                scan.setVulnerability(vuln);
                session.save(scan);
            }
            session.getTransaction().commit();
            session.close();
        }
    }

    private Vulnerability getVulnerability(String name, Session session) {
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
