package org.owasp.dependencytrack.dao;

import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface ApplicationDao {
    @SuppressWarnings("unchecked")
    @Transactional
    List<Application> listApplications();

    @Transactional
    void addApplication(Application application,
                        String version);

    @Transactional
    void updateApplication(int id, String name);

    @SuppressWarnings("unchecked")
    @Transactional
    void deleteApplication(int id);

    @SuppressWarnings("unchecked")
    @Transactional
    Set<Application> searchApplications(int libverid);

    @SuppressWarnings("unchecked")
    @Transactional
    List<ApplicationVersion> searchApplicationsVersion(int libverid);

    @SuppressWarnings("unchecked")
    @Transactional
    Set<Application> searchAllApplications(int libid);

    @SuppressWarnings("unchecked")
    @Transactional
    List<ApplicationVersion> searchAllApplicationsVersions(int libid);

    @SuppressWarnings("unchecked")
    @Transactional
    Set<Application> coarseSearchApplications(int vendorID);

    @SuppressWarnings("unchecked")
    @Transactional
    List<ApplicationVersion> coarseSearchApplicationVersions(int vendorID);
}
