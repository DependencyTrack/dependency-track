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
