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
package org.owasp.dependencytrack.dao;

import org.hibernate.Session;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.util.DCObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Repository;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * This class will dynamically generate native Dependency-Check reports.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
@Repository("reportDao")
@DependsOn({"libraryVersionDao", "vulnerabilityDao"})
public class ReportDaoImpl extends BaseDao implements ReportDao {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ReportDaoImpl.class);

    /**
     * Dependency-Check database properties
     */
    private static DatabaseProperties properties = null;

    @Autowired
    private LibraryVersionDao libraryVersionDao;

    @Autowired
    private VulnerabilityDao vulnerabilityDao;


    /**
     * Initializes Dependency-Check database properties one time
     */
    private synchronized void initializeProperties() {
        if (properties != null) {
            return;
        }
        CveDB cve = null;
        try {
            cve = new CveDB();
            cve.open();
            properties = cve.getDatabaseProperties();
        } catch (DatabaseException ex) {
            LOGGER.error("Unable to retrieve DB Properties", ex);
        } finally {
            if (cve != null) {
                cve.close();
            }
        }
    }

    /**
     * Dynamically generate a native Dependency-Check report for the specified Application Version.
     * The report is not persisted to a file, rather returned as a String.
     * @param applicationVersionId the Application Version ID to report on
     * @param format the format of the report (i.e. ALL, XML, HTML)
     * @return a String representation of a Dependency-Check report
     */
    public String generateDependencyCheckReport(final int applicationVersionId, ReportGenerator.Format format) {
        Session session = getSession();

        final ApplicationVersion applicationVersion = (ApplicationVersion) session.load(ApplicationVersion.class, applicationVersionId);
        final String appName = applicationVersion.getApplication().getName() + " " + applicationVersion.getVersion();
        final List<LibraryVersion> libraryVersionList = libraryVersionDao.getDependencies(applicationVersion);
        final List<org.owasp.dependencycheck.dependency.Dependency> dcDependencies = new ArrayList<>();

        vulnerabilityDao = new VulnerabilityDaoImpl();
        for (LibraryVersion libraryVersion: libraryVersionList) {
            final List<Vulnerability> vulnerabilities = vulnerabilityDao.getVulnsForLibraryVersion(libraryVersion);
            final org.owasp.dependencycheck.dependency.Dependency dcDependency = DCObjectMapper.toDCDependency(libraryVersion, vulnerabilities);
            dcDependencies.add(dcDependency);
        }

        Settings.initialize();
        if (properties == null) {
            initializeProperties();
        }
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();

            final Engine engine = new Engine(this.getClass().getClassLoader());
            final ReportGenerator reportGenerator = new ReportGenerator(appName, dcDependencies, engine.getAnalyzers(), properties);
            reportGenerator.generateReports(baos, format);
            engine.cleanup();
            return baos.toString("UTF-8");
        } catch (Exception e) {
            LOGGER.error("An error occurred generating a Dependency-Check report: " + e.getMessage());
        } finally {
            Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, true);
        }
        return null;
    }

}
