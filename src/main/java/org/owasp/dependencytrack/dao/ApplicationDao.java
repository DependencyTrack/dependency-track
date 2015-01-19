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
package org.owasp.dependencytrack.dao;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.owasp.dependencycheck.agent.DependencyCheckScanAgent;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencytrack.Constants;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationDependency;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.ScanResult;
import org.owasp.dependencytrack.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Repository
public class ApplicationDao {

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ApplicationDao.class);

    /**
     * The Hibernate SessionFactory
     */
    @Autowired
    private SessionFactory sessionFactory;

    /**
     * Returns a list of all applications.
     *
     * @return A List of all applications
     */
    @SuppressWarnings("unchecked")
    public List<Application> listApplications() {
        final Query query = sessionFactory.getCurrentSession().createQuery("FROM Application");
        return query.list();
    }

    /**
     * Adds an ApplicationVersion to the specified Application.
     *
     * @param application An Application
     * @param version     The ApplicationVersion to add
     */
    public void addApplication(Application application, String version) {
        final Session session = sessionFactory.openSession();
        session.beginTransaction();
        session.save(application);

        final ApplicationVersion applicationVersion = new ApplicationVersion();
        applicationVersion.setVersion(version);
        applicationVersion.setApplication(application);

        session.save(applicationVersion);
        session.getTransaction().commit();
        session.close();
    }

    /**
     * Updates the Application with the specified ID to the name specified.
     *
     * @param id   The ID of the Application
     * @param name The new name of the Application
     */
    public void updateApplication(int id, String name) {
        final Query query = sessionFactory.getCurrentSession().createQuery(
                "update Application set name=:name " + "where id=:id");

        query.setParameter("name", name);
        query.setParameter("id", id);
        query.executeUpdate();
    }

    /**
     * Deletes the Application with the specified ID.
     *
     * @param id The ID of the Application to delete
     */
    @SuppressWarnings("unchecked")
    public void deleteApplication(int id) {
        final Session session = sessionFactory.openSession();
        session.beginTransaction();
        final Application curapp = (Application) session.load(Application.class, id);

        Query query = session.createQuery(
                "from ApplicationVersion " + "where application=:curapp");
        query.setParameter("curapp", curapp);

        final List<ApplicationVersion> applicationVersions = query.list();

        for (ApplicationVersion curver : applicationVersions) {
            query = session.createQuery(
                    "from ApplicationDependency " + "where applicationVersion=:curver");
            query.setParameter("curver", curver);
            List<ApplicationDependency> applicationDependency;
            if (!query.list().isEmpty()) {
                applicationDependency = query.list();
                for (ApplicationDependency dependency : applicationDependency) {
                    session.delete(dependency);
                }
            }
            session.delete(curver);
        }
        session.delete(curapp);
        session.getTransaction().commit();
        session.close();
    }

    /**
     * Returns a Set of Applications that have a dependency on the specified LibraryVersion ID.
     *
     * @param libverid The ID of the LibraryVersion to search on
     * @return A Set of Applications
     */
    @SuppressWarnings("unchecked")
    public Set<Application> searchApplications(int libverid) {
        Query query = sessionFactory.getCurrentSession().createQuery("FROM LibraryVersion where id=:libverid");
        query.setParameter("libverid", libverid);
        final LibraryVersion libraryVersion = (LibraryVersion) query.list().get(0);
        query = sessionFactory.getCurrentSession().
                createQuery("FROM ApplicationDependency where libraryVersion=:libver");
        query.setParameter("libver", libraryVersion);

        final List<ApplicationDependency> apdep = query.list();
        final List<Integer> ids = new ArrayList<>();

        for (ApplicationDependency appdep : apdep) {
            ids.add(appdep.getApplicationVersion().getId());
        }

        if (!ids.isEmpty()) {
            query = sessionFactory.getCurrentSession().
                    createQuery("FROM ApplicationVersion as appver where appver.id in (:appverid)");
            query.setParameterList("appverid", ids);

            if (query.list().size() == 0) {
                return null;
            }

            final List<ApplicationVersion> newappver = query.list();
            final ArrayList<Application> newapp = new ArrayList<>();

            for (ApplicationVersion version : newappver) {
                newapp.add(version.getApplication());
            }
            return new HashSet<>(newapp);
        } else {
            return null;
        }
    }

    /**
     * Returns a List of ApplicationVersions that have a dependency on the specified LibraryVersion ID.
     *
     * @param libverid The ID of the LibraryVersion to search on
     * @return A List of ApplicationVersion objects
     */
    @SuppressWarnings("unchecked")
    public List<ApplicationVersion> searchApplicationsVersion(int libverid) {

        Query query = sessionFactory.getCurrentSession().createQuery("FROM LibraryVersion where id=:libverid");
        query.setParameter("libverid", libverid);
        final LibraryVersion libraryVersion = (LibraryVersion) query.list().get(0);
        query = sessionFactory.getCurrentSession().
                createQuery("FROM ApplicationDependency where libraryVersion=:libver");
        query.setParameter("libver", libraryVersion);

        final List<ApplicationDependency> apdep = query.list();
        final List<Integer> ids = new ArrayList<>();

        for (ApplicationDependency appdep : apdep) {
            ids.add(appdep.getApplicationVersion().getId());
        }
        if (!ids.isEmpty()) {
            query = sessionFactory.getCurrentSession().
                    createQuery(" FROM ApplicationVersion as appver where appver.id in (:appverid)");
            query.setParameterList("appverid", ids);

            return query.list();
        } else {
            return null;
        }
    }

    /**
     * Returns a Set of Applications that have a dependency on the specified Library ID.
     *
     * @param libid The ID of the Library to search on
     * @return A Set of Application objects
     */
    @SuppressWarnings("unchecked")
    public Set<Application> searchAllApplications(int libid) {

        Query query = sessionFactory.getCurrentSession().
                createQuery("select lib.versions FROM Library as lib where lib.id=:libid");
        query.setParameter("libid", libid);
        final List<LibraryVersion> libver = query.list();
        query = sessionFactory.getCurrentSession().
                createQuery("FROM ApplicationDependency as appdep where appdep.libraryVersion in (:libver)");
        query.setParameterList("libver", libver);

        final List<ApplicationDependency> apdep = query.list();
        final List<Integer> ids = new ArrayList<>();

        for (ApplicationDependency appdep : apdep) {
            ids.add(appdep.getApplicationVersion().getId());
        }
        if (!ids.isEmpty()) {

            query = sessionFactory.getCurrentSession().
                    createQuery("FROM ApplicationVersion as appver where appver.id in (:appverid)");
            query.setParameterList("appverid", ids);

            final List<ApplicationVersion> newappver = query.list();
            final ArrayList<Application> newapp = new ArrayList<>();

            for (ApplicationVersion version : newappver) {
                newapp.add(version.getApplication());
            }
            return new HashSet<>(newapp);
        } else {
            return null;
        }
    }

    /**
     * Returns a List of ApplicationVersions that have a dependency on the specified Library ID.
     *
     * @param libid The ID of the Library to search on
     * @return a List of ApplicationVersion objects
     */
    @SuppressWarnings("unchecked")
    public List<ApplicationVersion> searchAllApplicationsVersions(int libid) {

        Query query = sessionFactory.getCurrentSession().
                createQuery("select lib.versions FROM Library as lib where lib.id=:libid");
        query.setParameter("libid", libid);
        final List<LibraryVersion> libver = query.list();
        query = sessionFactory.getCurrentSession().
                createQuery("FROM ApplicationDependency as appdep where appdep.libraryVersion in (:libver)");
        query.setParameterList("libver", libver);

        final List<ApplicationDependency> apdep = query.list();
        final List<Integer> ids = new ArrayList<>();

        for (ApplicationDependency appdep : apdep) {
            ids.add(appdep.getApplicationVersion().getId());
        }
        if (!ids.isEmpty()) {
            query = sessionFactory.getCurrentSession().
                    createQuery("FROM ApplicationVersion as appver where appver.id in (:appverid)");
            query.setParameterList("appverid", ids);
            return query.list();
        } else {
            return null;
        }
    }

    /**
     * Returns a List of Application that have a library of this vendor.
     *
     * @param vendorID The ID of the Library to search on
     * @return a List of ApplicationVersion objects
     */
    @SuppressWarnings("unchecked")
    public Set<Application> coarseSearchApplications(int vendorID) {
        Query query = sessionFactory.getCurrentSession().
                createQuery("select lib.versions FROM Library as lib where lib.libraryVendor.id=:vendorID");
        query.setParameter("vendorID", vendorID);

        final List<LibraryVersion> libver = query.list();

        query = sessionFactory.getCurrentSession().
                createQuery("FROM ApplicationDependency as appdep where appdep.libraryVersion in (:libver)");
        query.setParameterList("libver", libver);

        final List<ApplicationDependency> apdep = query.list();
        final List<Integer> ids = new ArrayList<>();

        for (ApplicationDependency appdep : apdep) {
            ids.add(appdep.getApplicationVersion().getId());
        }
        if (!ids.isEmpty()) {

            query = sessionFactory.getCurrentSession().
                    createQuery("FROM ApplicationVersion as appver where appver.id in (:appverid)");
            query.setParameterList("appverid", ids);

            final List<ApplicationVersion> newappver = query.list();
            final ArrayList<Application> newapp = new ArrayList<>();

            for (ApplicationVersion version : newappver) {
                newapp.add(version.getApplication());
            }
            return new HashSet<>(newapp);
        } else {
            return null;
        }

    }

    /**
     * Returns a List of ApplicationVersions that have a dependency on the specified Library Vendor.
     *
     * @param vendorID The ID of the Vendor to search on
     * @return a List of ApplicationVersion objects
     */
    @SuppressWarnings("unchecked")
    public List<ApplicationVersion> coarseSearchApplicationVersions(int vendorID) {

        Query query = sessionFactory.getCurrentSession().
                createQuery("select lib.versions FROM Library as lib where lib.libraryVendor.id=:vendorID");
        query.setParameter("vendorID", vendorID);

        final List<LibraryVersion> libver = query.list();

        query = sessionFactory.getCurrentSession().
                createQuery("FROM ApplicationDependency as appdep where appdep.libraryVersion in (:libver)");
        query.setParameterList("libver", libver);

        final List<ApplicationDependency> apdep = query.list();
        final List<Integer> ids = new ArrayList<>();

        for (ApplicationDependency appdep : apdep) {
            ids.add(appdep.getApplicationVersion().getId());
        }
        if (!ids.isEmpty()) {
            query = sessionFactory.getCurrentSession().
                    createQuery("FROM ApplicationVersion as appver where appver.id in (:appverid)");
            query.setParameterList("appverid", ids);
            return query.list();
        } else {
            return null;
        }
    }

    /**
     * Returns a scan results of all the dependencies in the database
     * we generate reports which are stored in the home directory.
     * @param libraryHierarchyBody a String representation of the JSON library hierarchy
     */
    public void scanApplication(String libraryHierarchyBody) {
        try {
            final List<Dependency> allDep = new ArrayList<>();
            final JSONObject parse = (JSONObject) JSONValue.parse(libraryHierarchyBody);
            final JSONArray vendors = (JSONArray) parse.get("vendors");

            Dependency dependency = new Dependency(new File(FileUtils.getBitBucket()));

            for (Object ven : vendors) {
                final JSONObject vendor = (JSONObject) ven;
                final JSONArray libraries = (JSONArray) vendor.get("libraries");
                for (Object lib : libraries) {
                    final JSONObject libs = (JSONObject) lib;
                    final JSONArray versions = (JSONArray) libs.get("versions");
                    for (Object version : versions) {
                        final JSONObject ver = (JSONObject) version;
                        dependency.getVendorEvidence().addEvidence("dependency-track", "vendor", (String) vendor.get("vendor"), Confidence.HIGH);
                        dependency.getVersionEvidence().addEvidence("dependency-track", "libraryLanguage", (String) ver.get("libver"), Confidence.HIGH);
                        dependency.getProductEvidence().addEvidence("dependency-track", "libraryName", (String) libs.get("libname"), Confidence.HIGH);
                        final Identifier identifier = new Identifier("dependency-track", "libverid", String.valueOf(ver.get("libverid")), "Description");
                        identifier.setConfidence(Confidence.HIGH);
                        dependency.getIdentifiers().add(identifier);
                        allDep.add(dependency);
                        dependency = new Dependency(new File(FileUtils.getBitBucket()));
                    }
                }
            }

            final DependencyCheckScanAgent scanAgent = new DependencyCheckScanAgent();
            scanAgent.setConnectionString("jdbc:h2:file:%s;FILE_LOCK=SERIALIZED;AUTOCOMMIT=ON;");
            scanAgent.setDataDirectory(Constants.DATA_DIR);
            scanAgent.setAutoUpdate(true);

            scanAgent.setDependencies(allDep);
            scanAgent.setReportFormat(ReportGenerator.Format.ALL);
            scanAgent.setReportOutputDirectory(System.getProperty("user.home"));
            scanAgent.execute();

        } catch (Exception e) {
            LOGGER.error("An error occurred while attempting to perform a Dependency-Check scan against an application");
            LOGGER.error(e.getMessage());
        }
    }

    /**
     * Azalyzes the reports generated from the scan and extracts relevant data and creates record.
     */
    public void analyzeScanResults() {
        try {
            final FileInputStream file = new FileInputStream(
                    new File(System.getProperty("user.home") + "\\dependency-check-report.xml"));
            final DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
            final DocumentBuilder builder = builderFactory.newDocumentBuilder();
            final Document xmlDocument = builder.parse(file);
            final NodeList nList = xmlDocument.getElementsByTagName("dependency");
            final Session session = sessionFactory.openSession();
            session.beginTransaction();

            for (int i = 0; i < nList.getLength(); i++) {
                final Node currentNode = nList.item(i);
                if (currentNode.getNodeType() == Node.ELEMENT_NODE) {
                    final Element e = (Element) currentNode;
                    final NodeList identfier = e.getElementsByTagName("identifier");
                    String value = null;
                    for (int j = 0; j < identfier.getLength(); j++) {
                        final Element node = (Element) identfier.item(j);
                        value = node.getAttribute("type");
                        if (node.getAttribute("type").compareTo("dependency-track") == 0) {
                            value = node.getElementsByTagName("url").item(0).getTextContent();
                        }
                    }
                    final NodeList nodeList = e.getElementsByTagName("vulnerabilities");

                    if (nodeList.getLength() > 0) {
                        for (int j = 0; j < nodeList.getLength(); j++) {
                            final Element e1 = (Element) nodeList.item(j);
                            final NodeList n = e1.getElementsByTagName("vulnerability");
                            if (n != null) {
                                for (int k = 0; k < n.getLength(); k++) {
                                    final Element vuln = (Element) n.item(k);
                                    final Query query = session.
                                            createQuery("FROM LibraryVersion as libver where libver.id in (:libverid)");
                                    query.setParameter("libverid", Integer.parseInt(value));

                                    final LibraryVersion currentLibrary = (LibraryVersion) query.list().get(0);
                                    final ScanResult results = new ScanResult();
                                    final Date date = new Date();

                                    results.setScanDate(date);
                                    results.setLibraryVersion(currentLibrary);
                                    session.save(results);

                                    final Vulnerability vulnerability = new Vulnerability();
                                    vulnerability.setScanResult(results);
                                    vulnerability.setName(vuln.getElementsByTagName("name").item(0).getTextContent());
                                    vulnerability.setCvssScore(Float.parseFloat(vuln.getElementsByTagName("cvssScore").item(0).getTextContent()));
                                    vulnerability.setCwe(vuln.getElementsByTagName("cwe").item(0).getTextContent());
                                    vulnerability.setDescription(vuln.getElementsByTagName("description").item(0).getTextContent());
                                    session.save(vulnerability);
                                    session.getTransaction().commit();
                                }
                            }
                        }
                    }
                }
            }
            session.close();
        } catch (SAXException | IOException | ParserConfigurationException e) {
            LOGGER.error("An error occurred analyzing scan results");
            LOGGER.error(e.getMessage());
        }
    }
}
