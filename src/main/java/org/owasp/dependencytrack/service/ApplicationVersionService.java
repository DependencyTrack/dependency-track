package org.owasp.dependencytrack.service;

import org.owasp.dependencytrack.model.ApplicationVersion;
import org.springframework.transaction.annotation.Transactional;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface ApplicationVersionService {
    @Transactional
    ApplicationVersion getApplicationVersion(int id);

    @Transactional
    void deleteApplicationVersion(Integer id);

    @Transactional
    void addApplicationVersion(int appid, String appversion);

    @Transactional
    void cloneApplication(Integer applicationid, String applicationname);

    @Transactional
    void cloneApplicationVersion(Integer applicationid, String newversion, String applicationversion);

    @Transactional
    void updateApplicationVersion(int id, String appversion);
}
