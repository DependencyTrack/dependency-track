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

import org.owasp.dependencytrack.model.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface LibraryVersionDao {
    @SuppressWarnings("unchecked")
    @Transactional
    List<LibraryVendor> getLibraryHierarchy();

    @SuppressWarnings("unchecked")
    @Transactional
    List<LibraryVendor> getVendors();

    @SuppressWarnings("unchecked")
    @Transactional
    List<Library> getLibraries(int id);

    @SuppressWarnings("unchecked")
    @Transactional
    List<LibraryVersion> getVersions(int id);

    @SuppressWarnings("unchecked")
    @Transactional
    List<LibraryVersion> getDependencies(ApplicationVersion version);

    @SuppressWarnings("unchecked")
    @Transactional
    void addDependency(int appversionid, int libversionid);

    @SuppressWarnings("unchecked")
    @Transactional
    void deleteDependency(int appversionid, int libversionid);

    @Transactional
    void updateLibrary(int vendorid, int licenseid, int libraryid, int libraryversionid,
                       String libraryname, String libraryversion, String vendor,
                       String license, String language);

    @SuppressWarnings("unchecked")
                              @Transactional
    void removeLibrary(int id);

    @SuppressWarnings("unchecked")
                              @Transactional
    List<License> listLicense(Integer id);

    @SuppressWarnings("unchecked")
                              @Transactional
    List<LibraryVersion> allLibrary();

    @SuppressWarnings("unchecked")
                              @Transactional
    List<Library> uniqueLibrary();

    @SuppressWarnings("unchecked")
                              @Transactional
    List<License> uniqueLicense();

    @SuppressWarnings("unchecked")
                              @Transactional
    List<LibraryVendor> uniqueVendor();

    @SuppressWarnings("unchecked")
                              @Transactional
    List<String> uniqueLang();

    @SuppressWarnings("unchecked")
                              @Transactional
    List<String> uniqueVer();

    @SuppressWarnings("unchecked")
                              @Transactional
    void addLibraries(String libraryname, String libraryversion, String vendor,
                      String license, MultipartFile file, String language);

    @Transactional
    void uploadLicense(int licenseid, MultipartFile file, String editlicensename);

    @SuppressWarnings("unchecked")
    @Transactional
    List<LibraryVersion> keywordSearchLibraries(String searchTerm);

}
