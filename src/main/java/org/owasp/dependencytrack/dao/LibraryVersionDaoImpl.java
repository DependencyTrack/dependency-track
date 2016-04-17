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

import org.apache.commons.io.IOUtils;
import org.hibernate.Hibernate;
import org.hibernate.Query;
import org.hibernate.Session;
import org.owasp.dependencytrack.model.ApplicationDependency;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.model.Library;
import org.owasp.dependencytrack.model.LibraryVendor;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.ScanResult;
import org.owasp.dependencytrack.tasks.DependencyCheckAnalysisRequestEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Repository;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Blob;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;

@Repository("libraryVersionDao")
@SuppressWarnings("unchecked")
public class LibraryVersionDaoImpl extends BaseDao implements LibraryVersionDao {

    /**
     * Event publisher
     */
    @Autowired
    private ApplicationEventPublisher applicationEventPublisher;

    /**
     * Setup logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(LibraryVersionDaoImpl.class);

    /**
     * Returns a List of all LibraryVendors available in the application along with all child objects.
     *
     * @return A List of Libraries (Vendor, Library,Version) in a hierarchy
     */
    @SuppressWarnings("unchecked")
    public List<LibraryVendor> getLibraryHierarchy() {
        final Session session = getSession();
        final ArrayList<LibraryVendor> retlist = new ArrayList<>();
        final Query query = session.createQuery("FROM LibraryVendor order by vendor asc");
        for (LibraryVendor vendor : (List<LibraryVendor>) query.list()) {
            final Query query2 = session.
                    createQuery("FROM Library where libraryVendor=:vendor order by libraryname asc");
            query2.setParameter("vendor", vendor);
            final LinkedHashSet<Library> libraries = new LinkedHashSet<>(query2.list());
            vendor.setLibraries(libraries);
            for (Library library : (ArrayList<Library>) query2.list()) {
                final Query query3 = session.
                        createQuery("FROM LibraryVersion where library=:library order by libraryversion asc");
                query3.setParameter("library", library);
                final ArrayList<LibraryVersion> versions = (ArrayList<LibraryVersion>) query3.list();
                library.setVersions(new LinkedHashSet<>(versions));
            }
            retlist.add(vendor);
        }
        return retlist;
    }

    /**
     * Returns a List of all LibraryVendors.
     *
     * @return A List of all LibraryVendors
     */
    @SuppressWarnings("unchecked")
    public List<LibraryVendor> getVendors() {
        final Query query = getSession().createQuery("FROM LibraryVendor order by vendor asc");
        return query.list();
    }

    /**
     * Returns a List of all Libraries made by the specified LibraryVendor.
     *
     * @param vendor The Vendor of the Library
     * @return A List of Libraries
     */
    @SuppressWarnings("unchecked")
    public List<Library> getLibraries(LibraryVendor vendor) {
        final Query query = getSession().
                createQuery("FROM Library WHERE libraryVendor=:vendor order by libraryname asc");
        query.setParameter("vendor", vendor);
        return query.list();
    }

    /**
     * Returns a List of all LibraryVersions for the specified Library.
     *
     * @param library The Library to obtain versions of
     * @return A List of LibraryVersion objects
     */
    @SuppressWarnings("unchecked")
    public List<LibraryVersion> getVersions(Library library) {
        final Query query = getSession().
                createQuery("FROM LibraryVersion WHERE library=:library order by libraryversion asc");
        query.setParameter("library", library);
        return query.list();
    }

    /**
     * Returns a list of LibraryVersion objects that the specified ApplicationVersion has a dependency on.
     *
     * @param version An ApplicationVersion object
     * @return A List of LibraryVersion objects
     */
    @SuppressWarnings("unchecked")
    public List<LibraryVersion> getDependencies(final ApplicationVersion version) {
        final Query query = getSession().
                createQuery("from ApplicationDependency where applicationVersion=:version");
        query.setParameter("version", version);
        final List<LibraryVersion> libvers = new ArrayList<>();
        final List<ApplicationDependency> deps = query.list();
        for (ApplicationDependency dep : deps) {
            libvers.add(dep.getLibraryVersion());
        }
        return libvers;
    }

    /**
     * Adds a dependency between the ID of the specified ApplicationVersion and LibraryVersion.
     *
     * @param appversionid The ID of the ApplicationVersion
     * @param libversionid The ID of the LibraryVersion
     */
    @SuppressWarnings("unchecked")
    public void addDependency(final int appversionid, final int libversionid) {
        final Session session = getSession();
        final ApplicationVersion applicationVersion =
                (ApplicationVersion) session.load(ApplicationVersion.class, appversionid);
        final LibraryVersion libraryVersion =
                (LibraryVersion) session.load(LibraryVersion.class, libversionid);
        final ApplicationDependency dependency = new ApplicationDependency();
        dependency.setApplicationVersion(applicationVersion);
        dependency.setLibraryVersion(libraryVersion);
        session.save(dependency);
    }

    /**
     * Deletes the dependency between the ID of the specified ApplicationVersion and LibraryVersion.
     *
     * @param appversionid The ID of the ApplicationVersion
     * @param libversionid The ID of the LibraryVersion
     */
    @SuppressWarnings("unchecked")
    public void deleteDependency(final int appversionid, final int libversionid) {
        final Session session = getSession();
        session.beginTransaction();
        Query query = session.createQuery("from ApplicationVersion AS appver where appver.id=:appversionid");
        query.setParameter("appversionid", appversionid);

        final ApplicationVersion applicationVersion = (ApplicationVersion) query.list().get(0);

        query = session.createQuery("from LibraryVersion AS libver where libver.id=:libversionid");
        query.setParameter("libversionid", libversionid);

        final LibraryVersion libraryVersion = (LibraryVersion) query.list().get(0);

        query = session.createQuery("from ApplicationDependency AS appdep where appdep.libraryVersion=:libraryVersion and appdep.applicationVersion=:applicationVersion");
        query.setParameter("libraryVersion", libraryVersion);
        query.setParameter("applicationVersion", applicationVersion);

        final ApplicationDependency applicationDependency = (ApplicationDependency) query.list().get(0);

        session.delete(applicationDependency);
        session.getTransaction().commit();
    }

    /**
     * Updates a Library object.
     *
     * @param vendorid         The ID of the LibraryVendor
     * @param licenseid        The ID of the License
     * @param libraryid        The ID of the Library
     * @param libraryversionid The ID of the LibraryVersion
     * @param libraryname      The updated Library name
     * @param libraryversion   The updated version label
     * @param vendor           The updated vendor label
     * @param license          The updated license label
     * @param language         The updated programming language
     */
    public void updateLibrary(final int vendorid, final int licenseid, final int libraryid, final int libraryversionid,
                              final String libraryname, final String libraryversion, final String vendor,
                              final String license, final String language) {

        final Session session = getSession();
        Query query = session.createQuery("update LibraryVendor set vendor=:vendor where id=:vendorid");

        query.setParameter("vendorid", vendorid);
        query.setParameter("vendor", vendor);
        query.executeUpdate();

        query = session.createQuery("from LibraryVendor where id=:vendorid");
        query.setParameter("vendorid", vendorid);

        final LibraryVendor libraryVendor = (LibraryVendor) query.list().get(0);

        if (license == null || license.isEmpty()) {
            query = session.createQuery("from License where id=:id");
            query.setParameter("id", licenseid);
        } else {
            query = session.createQuery("from License where licensename=:name");
            query.setParameter("name", license);
        }
        final License licenses = (License) query.list().get(0);

        query = session.createQuery(
                "update Library set libraryname=:libraryname,"
                        + "license=:licenses,"
                        + "libraryVendor=:libraryVendor,"
                        + "language=:language " + "where id=:libraryid");

        query.setParameter("libraryname", libraryname);
        query.setParameter("licenses", licenses);

        query.setParameter("libraryVendor", libraryVendor);
        query.setParameter("language", language);
        query.setParameter("libraryid", libraryid);

        query.executeUpdate();

        query = session.createQuery("from Library where id=:libraryid");
        query.setParameter("libraryid", libraryid);
        final Library library = (Library) query.list().get(0);

        query = session.createQuery("update LibraryVersion set libraryversion=:libraryversion, library=:library where id=:libverid");

        query.setParameter("libraryversion", libraryversion);
        query.setParameter("library", library);
        query.setParameter("libverid", libraryversionid);
        query.executeUpdate();

        query = session.createQuery("from LibraryVersion where id=:libverid");
        query.setParameter("libverid", libraryversionid);
        applicationEventPublisher.publishEvent(new DependencyCheckAnalysisRequestEvent(this, query.list()));
    }

    /**
     * Remove the Library with the specified ID.
     *
     * @param id The ID of the Library to delete
     */
    @SuppressWarnings("unchecked")
    public void removeLibrary(final int id) {
        Session session = getSession();
        session.beginTransaction();
        Query querylib = session.createQuery("from LibraryVersion " + "where id=:libraryVersion");
        querylib.setParameter("libraryVersion", id);

        final LibraryVersion version = (LibraryVersion) querylib.list().get(0);


        final int libid = ((LibraryVersion) querylib.list().get(0)).getLibrary().getId();
        querylib = session.createQuery("select lib.versions from Library as lib " + "where lib.id=:libid");
        querylib.setParameter("libid", libid);

        final int count = querylib.list().size();

        final Query query = session.createQuery("from ApplicationDependency " + "where libraryVersion=:libraryVersion");

        query.setParameter("libraryVersion", version);
        List<ApplicationDependency> applicationDependency;

        final Query scanQuery = session.createQuery("from ScanResult s where libraryVersion=:libVerId");
        scanQuery.setParameter("libVerId", version);
        final List<ScanResult> scanResults = scanQuery.list();
        for (ScanResult scanResult : scanResults) {
            session.delete(scanResult);
        }

        if (!query.list().isEmpty() && count == 1) {

            applicationDependency = query.list();
            for (ApplicationDependency dependency : applicationDependency) {
                session.delete(dependency);
            }
            session.delete(version);
            final Library curlib = (Library) session.load(Library.class, libid);
            session.delete(curlib);
        } else if (version != null && count == 1) {
            session.delete(version);
            final Library curlib = (Library) session.load(Library.class, libid);
            final LibraryVendor vendor = curlib.getLibraryVendor();

            boolean deleteVendor = false;
            if (vendor.getLibraries().size() == 1) {
                deleteVendor = true;
            }

            session.delete(curlib);
            if (deleteVendor) {
                session.delete(vendor);
            }

        } else if (!query.list().isEmpty()) {
            applicationDependency = query.list();
            for (ApplicationDependency dependency : applicationDependency) {
                session.delete(dependency);
            }
            session.delete(version);
        } else if (version != null) {
            session.delete(version);
        }
        session.getTransaction().commit();
    }

    /**
     * Returns a List of License objects with the specified ID.
     *
     * @param id The ID of the License
     * @return A List of License objects
     */
    @SuppressWarnings("unchecked")
    public List<License> listLicense(final Integer id) {
        final Query query = getSession().createQuery("from License where id=:licid");
        query.setParameter("licid", id);
        return query.list();
    }

    /**
     * Returns a List of all LibraryVersions.
     *
     * @return a List of all LibraryVersion objects
     */
    @SuppressWarnings("unchecked")
    public List<LibraryVersion> allLibrary() {
        final Query query = getSession().
                createQuery("from LibraryVersion order by library.libraryVendor.vendor, library.libraryname");
        return query.list();
    }

    /**
     * Returns a List of Library objects.
     *
     * @return a List of Library objects
     */
    @SuppressWarnings("unchecked")
    public List<Library> uniqueLibrary() {
        final Query query = getSession().
                createQuery("select distinct l.libraryname from Library as l order by l.libraryname");
        return query.list();
    }

    /**
     * Returns a List of License objects.
     *
     * @return a List of License objects
     */
    @SuppressWarnings("unchecked")
    public List<License> uniqueLicense() {
        final Query query = getSession().
                createQuery("select distinct l.licensename from License as l order by l.licensename");
        return query.list();
    }

    /**
     * Returns a List of LibraryVendor objects.
     *
     * @return a List of LibraryVendor objects
     */
    @SuppressWarnings("unchecked")
    public List<LibraryVendor> uniqueVendor() {
        final Query query = getSession().
                createQuery("select distinct v.vendor from LibraryVendor as v order by v.vendor");
        return query.list();
    }

    /**
     * Returns a List of languages.
     *
     * @return a List of languages
     */
    @SuppressWarnings("unchecked")
    public List<String> uniqueLang() {
        final Query query = getSession().
                createQuery("select distinct lib.language from Library as lib order by lib.language");
        return query.list();
    }

    /**
     * Returns a List of LibraryVersion strings.
     *
     * @return a List of Strings containing the version number
     */
    @SuppressWarnings("unchecked")
    public List<String> uniqueVer() {
        final Query query = getSession().
                createQuery("select distinct libver.libraryversion from LibraryVersion as libver order by libver.libraryversion");
        return query.list();
    }

    /**
     * Add a Library + LibraryVersion.
     *
     * @param libraryname    The name of the Library
     * @param libraryversion The version of the Library
     * @param vendor         The vendor of the Library
     * @param license        The license the Library is licensed under
     * @param file           The license file
     * @param language       The programming language the library was written in
     */
    @SuppressWarnings("unchecked")
    public void addLibraries(final String libraryname, final String libraryversion, final String vendor,
                             final String license, final MultipartFile file, final String language) {
        final Session session = getSession();
        session.beginTransaction();
        LibraryVendor libraryVendor;
        License licenses;
        Library library;

        Query query = session.createQuery("from LibraryVendor where upper(vendor) =upper(:vendor) ");
        query.setParameter("vendor", vendor);

        if (query.list().isEmpty()) {
            libraryVendor = new LibraryVendor();
            libraryVendor.setVendor(vendor);
            session.save(libraryVendor);
        } else {
            libraryVendor = (LibraryVendor) query.list().get(0);
        }

        query = session.createQuery("from License where upper(licensename) =upper(:license) ");
        query.setParameter("license", license);


        if (query.list().isEmpty()) {
            licenses = new License();

            InputStream licenseInputStream = null;
            try {
                licenseInputStream = file.getInputStream();
                String licenceFileContent = new String(IOUtils.toCharArray(licenseInputStream));
                final Blob blob = Hibernate.getLobCreator(session).createBlob(licenceFileContent.getBytes());

                licenses.setFilename(file.getOriginalFilename());
                licenses.setContenttype(file.getContentType());
                licenses.setLicensename(license);
                licenses.setText(blob);
                session.save(licenses);

            } catch (IOException e) {
                LOGGER.error("An error occurred while adding a library with library version");
                LOGGER.error(e.getMessage());
            } finally {
                IOUtils.closeQuietly(licenseInputStream);
            }

        } else {
            licenses = (License) query.list().get(0);
        }

        query = session.createQuery("from Library as lib where upper(lib.libraryname) =upper(:libraryname) and lib.libraryVendor=:vendor ");
        query.setParameter("libraryname", libraryname);
        query.setParameter("vendor", libraryVendor);

        if (query.list().isEmpty()) {
            library = new Library();
            library.setLibraryname(libraryname);
            library.setLibraryVendor(libraryVendor);
            library.setLicense(licenses);

            library.setLanguage(language);
            session.save(library);
        } else {
            library = (Library) query.list().get(0);
        }

        query = session.createQuery("from LibraryVersion as libver where libver.library =:library "
                + "and libver.library.libraryVendor=:vendor and libver.libraryversion =:libver ");
        query.setParameter("library", library);
        query.setParameter("vendor", libraryVendor);
        query.setParameter("libver", libraryversion);

        if (query.list().isEmpty()) {
            final LibraryVersion libVersion = new LibraryVersion();
            libVersion.setLibrary(library);
            libVersion.setLibraryversion(libraryversion);
            libVersion.setUuid(UUID.randomUUID().toString());
            session.save(libVersion);
        }
        session.getTransaction().commit();

        query = session.createQuery("from LibraryVersion as libver where libver.library =:library "
                + "and libver.library.libraryVendor=:vendor and libver.libraryversion =:libver ");
        query.setParameter("library", library);
        query.setParameter("vendor", libraryVendor);
        query.setParameter("libver", libraryversion);
        final List<LibraryVersion> libraryVersions = query.list();

        applicationEventPublisher.publishEvent(new DependencyCheckAnalysisRequestEvent(this, libraryVersions));
    }

    public void uploadLicense(final int licenseid, final MultipartFile file, final String editlicensename) {
        Session session = getSession();
        InputStream licenseInputStream = null;
        try {
            Blob blob;
            final Query query;

            if (file.isEmpty()) {
                query = session.createQuery("update License set licensename=:lname where id=:licenseid");
                query.setParameter("licenseid", licenseid);
                query.setParameter("lname", editlicensename);
                query.executeUpdate();
            } else {
                licenseInputStream = file.getInputStream();
                String licenceFileContent = new String(IOUtils.toCharArray(licenseInputStream));
                blob = Hibernate.getLobCreator(session).createBlob(licenceFileContent.getBytes());
                query = session.createQuery(
                        "update License set licensename=:lname,"
                                + "text=:blobfile," + "filename=:filename,"
                                + "contenttype=:contenttype "
                                + "where id=:licenseid");

                query.setParameter("licenseid", licenseid);
                query.setParameter("lname", editlicensename);
                query.setParameter("blobfile", blob);
                query.setParameter("filename", file.getOriginalFilename());
                query.setParameter("contenttype", file.getContentType());
                query.executeUpdate();
            }
        } catch (IOException e) {
            LOGGER.error("An error occurred while uploading a license");
            LOGGER.error(e.getMessage());
        } finally {
            IOUtils.closeQuietly(licenseInputStream);
        }
    }

    /**
     * Returns a List of all LibraryVersions. based on search term
     *
     * @return a List of all LibraryVersion objects
     */
    @SuppressWarnings("unchecked")
    public List<LibraryVersion> keywordSearchLibraries(final String searchTerm) {
        final Query query = getSession().createQuery(
                "from LibraryVersion as libver where upper(libver.library.libraryname) "
                        + "LIKE upper(:searchTerm) or upper(libver.library.libraryVendor.vendor) "
                        + "LIKE upper(:searchTerm) order by libver.library.libraryname");
        query.setParameter("searchTerm", "%" + searchTerm + "%");
        return query.list();
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }
}
