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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.dependencytrack.config.JunitDatabaseConfiguration;
import org.owasp.dependencytrack.model.AllEntities;
import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.model.Library;
import org.owasp.dependencytrack.model.LibraryVendor;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.repository.AllRepositories;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {JunitDatabaseConfiguration.class,AllEntities.class,HibernateJpaAutoConfiguration.class, AllRepositories.class,AllDaos.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class LibraryVersionDaoTest {

    @Autowired
    ApplicationDao applicationDao;

    @Autowired
    ApplicationVersionDao applicationVersionDao;

    @Autowired
    LibraryVersionDao libraryVersionDao;

    @Test
    public void getLibraryHierarchyTest() throws IOException {
        libraryVersionDao.addLibraries("Library A", "1.0", "Vendor A", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library A", "2.0", "Vendor A", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library B", "1.0", "Vendor B", "License B", readLicense(), "Native");
        libraryVersionDao.addLibraries("Library C", "1.0", "Vendor B", "License B", readLicense(), "Native");

        List<LibraryVendor> vendors = libraryVersionDao.getLibraryHierarchy();
        assertEquals(2, vendors.size());

        for (LibraryVendor vendor: vendors) {
            if ("Vendor A".equals(vendor.getVendor())) {
                assertEquals(1, vendor.getLibraries().size());
                Library library = vendor.getLibraries().iterator().next();
                assertEquals("Library A", library.getLibraryname());
                assertEquals("Java", library.getLanguage());
                Iterator versionsIterator = library.getVersions().iterator();
                LibraryVersion version = (LibraryVersion)versionsIterator.next();
                assertEquals("1.0", version.getLibraryversion());
                assertNotNull(version.getUuid());
                assertNull(version.getMd5());
                assertNull(version.getSha1());
                assertNotNull(version.getUuidAsMd5Hash());
                assertNotNull(version.getUuidAsSha1Hash());
                assertEquals(new Integer(0), version.getVulnCount());
                version = (LibraryVersion)versionsIterator.next();
                assertEquals("2.0", version.getLibraryversion());
            } else {
                assertEquals(2, vendor.getLibraries().size());
                Iterator libraryIterator = vendor.getLibraries().iterator();
                Library b = (Library)libraryIterator.next();
                Library c = (Library)libraryIterator.next();
                assertEquals("Library B", b.getLibraryname());
                assertEquals("Library C", c.getLibraryname());
            }
        }
    }

    @Test
    public void getVendorsTest() throws IOException {
        libraryVersionDao.addLibraries("Library 0", "1.0", "Vendor 0", "License 0", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library 1", "1.0", "Vendor 1", "License 1", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library 2", "1.0", "Vendor 2", "License 2", readLicense(), "Native");
        libraryVersionDao.addLibraries("Library 3", "1.0", "Vendor 3", "License 3", readLicense(), "Native");

        List<LibraryVendor> vendors = libraryVersionDao.getVendors();
        assertEquals(4, vendors.size());
        for (int i=0; i<vendors.size(); i++) {
            LibraryVendor vendor = vendors.get(i);
            assertEquals("Vendor " + i, vendor.getVendor());
            Library library = vendor.getLibraries().iterator().next();
            assertEquals("Library " + i, library.getLibraryname());
        }
    }

    @Test
    public void getLibrariesTest() throws Exception {
        libraryVersionDao.addLibraries("Library 3", "1.0", "Vendor A", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library 0", "1.0", "Vendor A", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library 1", "1.0", "Vendor A", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library 2", "1.0", "Vendor A", "License A", readLicense(), "Java");

        libraryVersionDao.addLibraries("Library 1", "1.0", "Vendor B", "License B", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library 2", "1.0", "Vendor B", "License B", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library 3", "1.0", "Vendor B", "License B", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library 0", "1.0", "Vendor B", "License B", readLicense(), "Java");

        List<LibraryVendor> vendors = libraryVersionDao.getVendors();
        assertEquals(2, vendors.size());
        for (LibraryVendor vendor: vendors) {
            List<Library> libraries = libraryVersionDao.getLibraries(vendor);
            for (int i = 0; i < libraries.size(); i++) {
                assertEquals(4, libraries.size());
                assertEquals("Library " + i, libraries.get(i).getLibraryname());
            }
        }
    }

    @Test
    public void getVersionsTest() throws Exception {
        libraryVersionDao.addLibraries("Library A", "2.0", "Vendor A", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library A", "3.1", "Vendor A", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library A", "3.0", "Vendor A", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library A", "3.2", "Vendor A", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library A", "1.0", "Vendor A", "License A", readLicense(), "Java");

        List<LibraryVendor> vendors = libraryVersionDao.getVendors();
        for (LibraryVendor vendor: vendors) {
            List<Library> libraries = libraryVersionDao.getLibraries(vendor);
            assertEquals(1, libraries.size());

            List<LibraryVersion> versions = libraryVersionDao.getVersions(libraries.get(0));
            assertEquals(5, versions.size());
            Iterator vi = versions.iterator();
            LibraryVersion version = (LibraryVersion)vi.next();
            assertEquals("1.0", version.getLibraryversion());
            version = (LibraryVersion)vi.next();
            assertEquals("2.0", version.getLibraryversion());
            version = (LibraryVersion)vi.next();
            assertEquals("3.0", version.getLibraryversion());
            version = (LibraryVersion)vi.next();
            assertEquals("3.1", version.getLibraryversion());
            version = (LibraryVersion)vi.next();
            assertEquals("3.2", version.getLibraryversion());
        }
    }

    @Test
    public void dependenciesTest() throws Exception {
        Application application = new Application();
        application.setName("Application A");
        applicationDao.addApplication(application, "1.0.0");

        ApplicationVersion appVersion = (ApplicationVersion)applicationDao.getSession()
                .createCriteria(ApplicationVersion.class).list().get(0);
        libraryVersionDao.addLibraries("Library A", "1.0", "Vendor A", "License A", readLicense(), "Java");
        LibraryVersion libraryVersion = (LibraryVersion)libraryVersionDao.getSession()
                .createCriteria(LibraryVersion.class).list().get(0);

        List<LibraryVersion> dependencies = libraryVersionDao.getDependencies(appVersion);
        assertEquals(0, dependencies.size());

        libraryVersionDao.addDependency(appVersion.getId(), libraryVersion.getId());
        dependencies = libraryVersionDao.getDependencies(appVersion);
        assertEquals(1, dependencies.size());

        libraryVersionDao.deleteDependency(appVersion.getId(), libraryVersion.getId());
        dependencies = libraryVersionDao.getDependencies(appVersion);
        assertEquals(0, dependencies.size());
    }

    @Test
    public void updateLibraryTest() throws Exception {
        libraryVersionDao.addLibraries("Library A", "1.0", "Vendor A", "License A", readLicense(), "Java");

        List<LibraryVendor> vendors = libraryVersionDao.getVendors();
        LibraryVendor vendor = vendors.get(0);
        Library library = vendor.getLibraries().iterator().next();
        LibraryVersion version = library.getVersions().iterator().next();
        License license = library.getLicense();

        libraryVersionDao.updateLibrary(vendor.getId(), license.getId(), library.getId(), version.getId(), "New Library A", "1.0a", "Vendor B", null, "Java");

        vendors = libraryVersionDao.getVendors();
        assertEquals(1, vendors.size());

        List<Library> libraries = libraryVersionDao.getLibraries(vendor);
        assertEquals(1, libraries.size());

        library = libraries.get(0);
        assertEquals("New Library A", library.getLibraryname());

        List<LibraryVersion> versions = libraryVersionDao.getVersions(library);
        assertEquals(1, versions.size());

        version = versions.get(0);
        assertEquals("1.0a", version.getLibraryversion());
    }

    @Test
    public void removeLibraryTest() throws Exception {
        libraryVersionDao.addLibraries("Library A", "1.0", "Vendor A", "License A", readLicense(), "Java");

        Library library = (Library) libraryVersionDao.getSession().createCriteria(Library.class).list().get(0);
        assertEquals("Library A", library.getLibraryname());

        LibraryVersion version = library.getVersions().iterator().next();

        libraryVersionDao.removeLibrary(version.getId());

        List<LibraryVersion> versions = libraryVersionDao.getSession().createCriteria(LibraryVersion.class).list();
        assertEquals(0, versions.size());
    }

    @Test
    public void listLicenseTest() throws Exception {
        libraryVersionDao.addLibraries("Library A", "1.0", "Vendor A", "License A", readLicense(), "Java");

        License license = (License)libraryVersionDao.getSession().createCriteria(License.class).list().get(0);

        List<License> licenses = libraryVersionDao.listLicense(license.getId());
        assertEquals(1, licenses.size());
        assertEquals("License A", license.getLicensename());
    }

    @Test
    public void allLibraryTest() throws Exception {
        libraryVersionDao.addLibraries("Library CB", "1.0", "Vendor C", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library DA", "1.0", "Vendor D", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library BB", "1.0", "Vendor B", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library AA", "1.0", "Vendor A", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library CA", "1.0", "Vendor C", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library BA", "1.0", "Vendor B", "License A", readLicense(), "Java");
        libraryVersionDao.addLibraries("Library AB", "1.0", "Vendor A", "License A", readLicense(), "Java");

        List<LibraryVersion> versions = libraryVersionDao.allLibrary();

        assertEquals(7, versions.size());
        assertEquals("Vendor A", versions.get(0).getLibrary().getLibraryVendor().getVendor());
        assertEquals("Vendor A", versions.get(1).getLibrary().getLibraryVendor().getVendor());
        assertEquals("Vendor B", versions.get(2).getLibrary().getLibraryVendor().getVendor());
        assertEquals("Vendor B", versions.get(3).getLibrary().getLibraryVendor().getVendor());
        assertEquals("Vendor C", versions.get(4).getLibrary().getLibraryVendor().getVendor());
        assertEquals("Vendor C", versions.get(5).getLibrary().getLibraryVendor().getVendor());
        assertEquals("Vendor D", versions.get(6).getLibrary().getLibraryVendor().getVendor());

        assertEquals("Library AA", versions.get(0).getLibrary().getLibraryname());
        assertEquals("Library AB", versions.get(1).getLibrary().getLibraryname());
        assertEquals("Library BA", versions.get(2).getLibrary().getLibraryname());
        assertEquals("Library BB", versions.get(3).getLibrary().getLibraryname());
        assertEquals("Library CA", versions.get(4).getLibrary().getLibraryname());
        assertEquals("Library CB", versions.get(5).getLibrary().getLibraryname());
        assertEquals("Library DA", versions.get(6).getLibrary().getLibraryname());
    }

    @Test
    public void uniqueLibraryTest() {
        //// TODO: 3/11/16
    }

    @Test
    public void uniqueLicenseTest() {
        //// TODO: 3/11/16
    }

    @Test
    public void uniqueVendorTest() {
        //// TODO: 3/11/16
    }

    @Test
    public void uniqueLangTest() {
        //// TODO: 3/11/16
    }

    @Test
    public void uniqueVerTest() {
        //// TODO: 3/11/16
    }

    @Test
    public void uploadLicenseTest() throws Exception {
        libraryVersionDao.addLibraries("Library A", "1.0", "Vendor A", "Apache License 2.0", readLicense(), "Java");

        License license = (License)libraryVersionDao.getSession().createCriteria(License.class).list().get(0);

        libraryVersionDao.uploadLicense(license.getId(), readLicense(new File("src/main/resources/licenses/GNU/gpl-3.0.txt")), "New Name");
        license = (License)libraryVersionDao.getSession().createCriteria(License.class).list().get(0);
        assertEquals("New Name", license.getLicensename());
        String text = new String(license.getText().getBytes(1, (int)license.getText().length()));
        assertTrue(text.trim().startsWith("GNU GENERAL PUBLIC LICENSE"));
    }

    @Test
    public void keywordSearchLibrariesTest() throws Exception {
        libraryVersionDao.addLibraries("Library A", "1.0", "Vendor A", "Apache License 2.0", readLicense(), "Java");

        List<LibraryVersion> versions = libraryVersionDao.keywordSearchLibraries("Blah");
        assertEquals(0, versions.size());

        versions = libraryVersionDao.keywordSearchLibraries("Library");
        assertEquals(1, versions.size());

        versions = libraryVersionDao.keywordSearchLibraries("rary");
        assertEquals(1, versions.size());

        versions = libraryVersionDao.keywordSearchLibraries("dor");
        assertEquals(1, versions.size());
    }

    private MultipartFile readLicense() throws IOException {
        return readLicense(new File("src/main/resources/licenses/Apache/LICENSE-2.0.txt"));
    }

    private MultipartFile readLicense(File file) throws IOException {
        FileInputStream input = new FileInputStream(file);
        return new MockMultipartFile("file", file.getName(), "text/plain", IOUtils.toByteArray(input));
    }

}