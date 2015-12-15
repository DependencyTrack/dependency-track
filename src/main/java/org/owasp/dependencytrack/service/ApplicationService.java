package org.owasp.dependencytrack.service;

import org.owasp.dependencytrack.model.Application;
import org.owasp.dependencytrack.model.ApplicationVersion;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface ApplicationService {
    @Transactional
    List<Application> listApplications();

    @Transactional
    void addApplication(Application application, String version);

    @Transactional
    void updateApplication(int id, String name);

    @Transactional
    void deleteApplication(int id);

    @Transactional
    Set<Application> searchApplications(int libverid);

    @Transactional
    Set<Application> searchAllApplications(int libid);

    @Transactional
    List<ApplicationVersion> searchApplicationsVersion(int libverid);

    @Transactional
    List<ApplicationVersion> searchAllApplicationsVersions(int libid);

    @Transactional
    Set<Application> coarseSearchApplications(int libid);

    @Transactional
    List<ApplicationVersion> coarseSearchApplicationVersions(int libid);
}
