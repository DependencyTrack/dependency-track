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

import org.owasp.dependencytrack.dao.LibraryVersionDao;
import org.owasp.dependencytrack.model.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Service
public class LibraryVersionServiceImpl implements LibraryVersionService {

    @Autowired
    private LibraryVersionDao libraryVersionDao;


    @Override
    @Transactional
    public List<LibraryVersion> getDependencies(ApplicationVersion version) {
        return libraryVersionDao.getDependencies(version);
    }

    @Override
    @Transactional
    public void addDependency(int appversionid, int libversionid) {
        libraryVersionDao.addDependency(appversionid, libversionid);
    }

    @Override
    @Transactional
    public void deleteDependency(int appversionid, int libversionid) {
        libraryVersionDao.deleteDependency(appversionid, libversionid);
    }

    /*
        Returns a List of all LibraryVendors available in the application along with all child objects
     */
    @Override
    @Transactional
    public List<LibraryVendor> getLibraryHierarchy() {
        return libraryVersionDao.getLibraryHierarchy();
    }



    @Override
    @Transactional
    public void updateLibrary(int vendorid, int licenseid, int libraryid,
                              int libraryversionid, String libraryname, String libraryversion,
                              String vendor, String license, String language) {

        libraryVersionDao.updateLibrary(vendorid, licenseid, libraryid,
                libraryversionid, libraryname, libraryversion, vendor, license, language);
    }

    @Override
    @Transactional
    public void removeLibrary(Integer id) {
        libraryVersionDao.removeLibrary(id);
    }

    @Override
    @Transactional
    public List<License> listLicense(Integer id) {
        return libraryVersionDao.listLicense(id);
    }

    @Override
    @Transactional
    public List<LibraryVersion> allLibrary() {
        return libraryVersionDao.allLibrary();
    }

    @Override
    @Transactional
    public List<Library> uniqueLibrary() {
        return libraryVersionDao.uniqueLibrary();
    }

    @Override
    @Transactional
    public List<License> uniqueLicense() {
        return libraryVersionDao.uniqueLicense();
    }

    @Override
    @Transactional
    public List<LibraryVendor> uniqueVendor() {
        return libraryVersionDao.uniqueVendor();
    }

    @Override
    @Transactional
    public List<String> uniqueLang() {
        return libraryVersionDao.uniqueLang();
    }

    @Override
    @Transactional
    public List<String> uniqueVer() {
        return libraryVersionDao.uniqueVer();
    }

    @Override
    @Transactional
    public void addLibraries(String libraryname, String libraryversion, String vendor, String license, MultipartFile file, String language) {

        libraryVersionDao.addLibraries(libraryname, libraryversion, vendor,  license,  file,  language);
    }

    @Override
    @Transactional
    public void uploadLicense(int licenseid, MultipartFile file, String editlicensename) {
        libraryVersionDao.uploadLicense(licenseid, file, editlicensename);
    }

    @Override
    @Transactional
    public List<LibraryVersion> keywordSearchLibraries(String searchTerm) {
        return libraryVersionDao.keywordSearchLibraries(searchTerm);
    }

}
