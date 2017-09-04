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
package org.owasp.dependencytrack.tasks;

import alpine.Config;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.resources.OrderDirection;
import alpine.resources.Pagination;
import org.apache.commons.lang.StringUtils;
import org.owasp.dependencycheck.agent.DependencyCheckScanAgent;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.exception.ScanAgentException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencytrack.event.DependencyCheckEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.persistence.QueryManager;
import java.io.File;
import java.util.ArrayList;
import java.util.List;


public class DependencyCheckTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(DependencyCheckTask.class);

    public void inform(Event e) {
        if (e instanceof DependencyCheckEvent) {
            LOGGER.info("Executing Dependency-Check Task");
            final DependencyCheckEvent event = (DependencyCheckEvent) e;

            if (event.analyzePortfolio()) {
                LOGGER.info("Analyzing portfolio");
                final AlpineRequest alpineRequest = new AlpineRequest(
                        null,
                        new Pagination(Pagination.Strategy.OFFSET, 0, 1000),
                        null,
                        "id",
                        OrderDirection.ASCENDING
                );

                try (QueryManager qm = new QueryManager(alpineRequest)) {
                    final long total = qm.getCount(Component.class);
                    long count = 0;
                    while (count < total) {
                        final PaginatedResult result = qm.getComponents();
                        analyze(result.getList(Component.class));
                        count += result.getTotal();
                        qm.advancePagination();
                    }
                }
            } else {
                LOGGER.info("Analyzing " + event.getComponents().size() + " component(s)");
                analyze(event.getComponents());
            }
        }
    }

    private void analyze(List<Component> components) {
        // Iterate through the components, create evidence, and create the resulting dependency
        final List<org.owasp.dependencycheck.dependency.Dependency> dependencies = new ArrayList<>();
        for (Component component: components) {
            final boolean isVirtual = !(StringUtils.isNotBlank(component.getMd5()) || StringUtils.isNotBlank(component.getSha1()));
            final org.owasp.dependencycheck.dependency.Dependency dependency =
                    new org.owasp.dependencycheck.dependency.Dependency(
                            new File(FileUtils.getBitBucket()),
                            isVirtual
                    );
            // Sets hashes if exists
            if (StringUtils.isNotBlank(component.getMd5())) {
                dependency.setMd5sum(component.getMd5());
            }
            if (StringUtils.isNotBlank(component.getSha1())) {
                dependency.setSha1sum(component.getSha1());
            }
            // Sets licenses if exists
            if (component.getResolvedLicense() != null) {
                dependency.setLicense(component.getResolvedLicense().getName());
            } else if (component.getLicense() != null) {
                dependency.setLicense(component.getLicense());
            }

            dependency.setDescription(String.valueOf(component.getUuid()));
            // Add evidence to the dependency
            if (component.getGroup() != null) {
                dependency.getVendorEvidence().addEvidence("dependency-track", "vendor", component.getGroup(), Confidence.HIGHEST);
            }
            if (component.getName() != null) {
                dependency.getProductEvidence().addEvidence("dependency-track", "name", component.getName(), Confidence.HIGHEST);
            }
            if (component.getVersion() != null) {
                dependency.getVersionEvidence().addEvidence("dependency-track", "version", component.getVersion(), Confidence.HIGHEST);
            }
            dependencies.add(dependency);
        }

        LOGGER.info("Performing Dependency-Check analysis against " + dependencies.size() + " component(s)");

        final String dcRootDir = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "dependency-check";
        final DependencyCheckScanAgent scanAgent = new DependencyCheckScanAgent();
        scanAgent.setConnectionString("jdbc:h2:file:%s;MV_STORE=FALSE;AUTOCOMMIT=ON;LOCK_MODE=0;FILE_LOCK=NO");
        scanAgent.setDataDirectory(dcRootDir + File.separator + "data");
        scanAgent.setReportOutputDirectory(dcRootDir + File.separator + "reports");
        scanAgent.setReportFormat(ReportGenerator.Format.XML);
        scanAgent.setAutoUpdate(true);
        scanAgent.setDependencies(dependencies);
        scanAgent.setCentralAnalyzerEnabled(false);
        scanAgent.setNexusAnalyzerEnabled(false);

        // If a global suppression file exists, use it.
        final File suppressions = new File(dcRootDir + File.separator + "suppressions.xml");
        if (suppressions.exists() && suppressions.isFile()) {
            scanAgent.setSuppressionFile(suppressions.getAbsolutePath());
        }

        try {
            scanAgent.execute();
        } catch (ScanAgentException ex) {
            LOGGER.error("An error occurred executing Dependency-Check scan agent: " + ex);
        }
        LOGGER.info("Dependency-Check analysis complete");
    }
}
