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
package org.owasp.dependencytrack.service;

import org.owasp.dependencytrack.model.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface LibraryVersionService {
    @Transactional
    List<LibraryVersion> getDependencies(ApplicationVersion version);

    @Transactional
    void addDependency(int appversionid, int libversionid);

    @Transactional
    void deleteDependency(int appversionid, int libversionid);

    /*
            Returns a List of all LibraryVendors available in the application along with all child objects
         */
    @Transactional
    List<LibraryVendor> getLibraryHierarchy();

    @Transactional
    void updateLibrary(int vendorid, int licenseid, int libraryid,
                       int libraryversionid, String libraryname, String libraryversion,
                       String vendor, String license, String language);

    @Transactional
    void removeLibrary(Integer id);

    @Transactional
    List<License> listLicense(Integer id);

    @Transactional
    List<LibraryVersion> allLibrary();

    @Transactional
    List<Library> uniqueLibrary();

    @Transactional
    List<License> uniqueLicense();

    @Transactional
    List<LibraryVendor> uniqueVendor();

    @Transactional
    List<String> uniqueLang();

    @Transactional
    List<String> uniqueVer();

    @Transactional
    void addLibraries(String libraryname, String libraryversion, String vendor, String license, MultipartFile file, String language);

    @Transactional
    void uploadLicense(int licenseid, MultipartFile file, String editlicensename);

    @Transactional
    List<LibraryVersion> keywordSearchLibraries(String searchTerm);
}
