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

import org.owasp.dependencytrack.model.ApplicationVersion;
import org.owasp.dependencytrack.model.Library;
import org.owasp.dependencytrack.model.LibraryVendor;
import org.owasp.dependencytrack.model.LibraryVersion;
import org.owasp.dependencytrack.model.License;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface LibraryVersionDao extends IBaseDao {

    @SuppressWarnings("unchecked")
    List<LibraryVendor> getLibraryHierarchy();

    @SuppressWarnings("unchecked")
    List<LibraryVendor> getVendors();

    @SuppressWarnings("unchecked")
    List<Library> getLibraries(LibraryVendor vendor);

    @SuppressWarnings("unchecked")
    List<LibraryVersion> getVersions(Library library);

    @SuppressWarnings("unchecked")
    List<LibraryVersion> getDependencies(ApplicationVersion version);

    @SuppressWarnings("unchecked")
    void addDependency(int appversionid, int libversionid);

    @SuppressWarnings("unchecked")
    void deleteDependency(int appversionid, int libversionid);

    void updateLibrary(int vendorid, int licenseid, int libraryid, int libraryversionid,
                       String libraryname, String libraryversion, String vendor,
                       String license, String language);

    @SuppressWarnings("unchecked")
    void removeLibrary(int id);

    @SuppressWarnings("unchecked")
    List<License> listLicense(Integer id);

    @SuppressWarnings("unchecked")
    List<LibraryVersion> allLibrary();

    @SuppressWarnings("unchecked")
    List<Library> uniqueLibrary();

    @SuppressWarnings("unchecked")
    List<License> uniqueLicense();

    @SuppressWarnings("unchecked")
    List<LibraryVendor> uniqueVendor();

    @SuppressWarnings("unchecked")
    List<String> uniqueLang();

    @SuppressWarnings("unchecked")
    List<String> uniqueVer();

    @SuppressWarnings("unchecked")
    void addLibraries(String libraryname, String libraryversion, String vendor,
                      String license, MultipartFile file, String language);

    void uploadLicense(int licenseid, MultipartFile file, String editlicensename);

    @SuppressWarnings("unchecked")
    List<LibraryVersion> keywordSearchLibraries(String searchTerm);

}
