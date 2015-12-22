package org.owasp.dependencytrack.dao;

import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.springframework.transaction.annotation.Transactional;

/**
 * Created by Jason Wraxall on 1/12/15.
 */
public interface ReportDao {
    @Transactional
    String generateDependencyCheckReport(int applicationVersionId, ReportGenerator.Format format);
}
