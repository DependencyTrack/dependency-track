/*
 * Copyright 2013 OWASP Foundation
 *
 * This file is part of OWASP Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with Dependency-Track.
 * If not, see http://www.gnu.org/licenses/.
 */

package org.owasp.dependencytrack.service;

import org.owasp.dependencytrack.dao.LibraryVersionDao;
import org.owasp.dependencytrack.model.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Service
public class LibraryVersionService {

    @Autowired
    private LibraryVersionDao libraryVersionDao;

    @Transactional
    public void addLibraryVersion(int appversionid, String libraryname,
                                  String libraryversion, String vendor, String license, MultipartFile file,
                                  String language, int secuniaID) {

        libraryVersionDao.addLibraryVersion(appversionid, libraryname,
                libraryversion, vendor, license, file, language, secuniaID);
    }

    @Transactional
    public List<ApplicationDependency> listLibraryVersion(int appversionid) {
        return libraryVersionDao.listLibraryVersion(appversionid);
    }

    @Transactional
    public List<LibraryVersion> getDependencies(ApplicationVersion version) {
        return libraryVersionDao.getDependencies(version);
    }

    @Transactional
    public void addDependency(int appversionid, int libversionid) {
        libraryVersionDao.addDependency(appversionid, libversionid);
    }

    @Transactional
    public void deleteDependency(int appversionid, int libversionid) {
        libraryVersionDao.deleteDependency(appversionid, libversionid);
    }

    /*
        Returns a List of all LibraryVendors available in the application along with all child objects
     */
    @Transactional
    public List<LibraryVendor> getLibraryHierarchy() {
        return libraryVersionDao.getLibraryHierarchy();
    }

    /*
        Returns a List of all LibraryVendors available in the application
     */
    @Transactional
    public List<LibraryVendor> getVendors() {
        return libraryVersionDao.getVendors();
    }

    /*
        Returns a List of all Libraries made by the specified LibraryVendor
     */
    @Transactional
    public List<Library> getLibraries(int id) {
        return libraryVersionDao.getLibraries(id);
    }

    /*
        Returns a List of all LibraryVersions for the specified Library
     */
    @Transactional
    public List<LibraryVersion> getVersions(int id) {
        return libraryVersionDao.getVersions(id);
    }

    @Transactional
    public void updateLibrary(int vendorid, int licenseid, int libraryid,
                              int libraryversionid, String libraryname, String libraryversion,
                              String vendor, String license, MultipartFile file, String language, int secuniaID) {

        libraryVersionDao.updateLibrary(vendorid, licenseid, libraryid,
                libraryversionid, libraryname, libraryversion, vendor, license, file,
                language, secuniaID);
    }

    @Transactional
    public void removeLibrary(Integer id) {
        libraryVersionDao.removeLibrary(id);
    }

    @Transactional
    public List<License> listLicense(Integer id) {
        return libraryVersionDao.listLicense(id);
    }

    @Transactional
    public List<LibraryVersion> allLibrary() {
        return libraryVersionDao.allLibrary();
    }

}