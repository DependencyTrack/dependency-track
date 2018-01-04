/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
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
import org.owasp.dependencycheck.agent.DependencyCheckScanAgent;
import org.owasp.dependencycheck.exception.ScanAgentException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencytrack.event.DependencyCheckEvent;
import org.owasp.dependencytrack.exception.ParseException;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.parser.dependencycheck.DependencyCheckParser;
import org.owasp.dependencytrack.parser.dependencycheck.model.Analysis;
import org.owasp.dependencytrack.parser.dependencycheck.util.ModelConverter;
import org.owasp.dependencytrack.persistence.QueryManager;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Subscriber task that performs a Dependency-Check analysis or update.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class DependencyCheckTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(DependencyCheckTask.class);
    private static final String DC_ROOT_DIR = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "dependency-check";
    private static final String DC_DATA_DIR = DC_ROOT_DIR + File.separator + "data";
    private static final String DC_REPORT_DIR = DC_ROOT_DIR + File.separator + "reports";
    private static final String DC_REPORT_FILE = DC_REPORT_DIR + File.separator + "dependency-check-report.xml";
    private static final String DC_GLOBAL_SUPPRESSION = DC_ROOT_DIR + File.separator + "suppressions.xml";

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof DependencyCheckEvent) {
            final DependencyCheckEvent event = (DependencyCheckEvent) e;
            if (DependencyCheckEvent.Action.ANALYZE == event.getAction()) {
                performAnalysis(event);
            } else if (DependencyCheckEvent.Action.UPDATE_ONLY == event.getAction()) {
                performUpdateOnly(event);
            }
        }
    }

    /**
     * Perfors a Dependency-Check analysis.
     * @param event a DependencyCheckEvent
     */
    private void performAnalysis(DependencyCheckEvent event) {
        LOGGER.info("Executing Dependency-Check analysis task");
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
                    count += result.getObjects().size();
                    qm.advancePagination();
                }
            }
        } else {
            analyze(event.getComponents());
        }
    }

    /**
     * Performs an update of the Dependeny-Check data directory only.
     * @param event a DependencyCheckEvent
     */
    private void performUpdateOnly(DependencyCheckEvent event) {
        LOGGER.info("Executing Dependency-Check update-only task");
        final DependencyCheckScanAgent scanAgent = new DependencyCheckScanAgent();
        scanAgent.setDataDirectory(DC_DATA_DIR);
        scanAgent.setAutoUpdate(true);
        scanAgent.setUpdateOnly(true);
        scanAgent.setProxyServer(Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_ADDRESS));
        scanAgent.setProxyPort(Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_PORT));
        scanAgent.setProxyUsername(Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_USERNAME));
        scanAgent.setProxyPassword(Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_PASSWORD));

        try {
            scanAgent.execute();
        } catch (ScanAgentException ex) {
            LOGGER.error("An error occurred executing Dependency-Check scan agent: " + ex);
        }
        LOGGER.info("Dependency-Check update-only complete");
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    private void analyze(List<Component> components) {
        // Iterate through the components, create evidence, and create the resulting dependency
        final List<org.owasp.dependencycheck.dependency.Dependency> dependencies = new ArrayList<>();
        for (Component component: components) {
            dependencies.add(ModelConverter.convert(component));
        }

        LOGGER.info("Analyzing " + dependencies.size() + " component(s)");

        final DependencyCheckScanAgent scanAgent = new DependencyCheckScanAgent();
        scanAgent.setDataDirectory(DC_DATA_DIR);
        scanAgent.setReportOutputDirectory(DC_REPORT_DIR);
        scanAgent.setReportFormat(ReportGenerator.Format.XML);
        scanAgent.setAutoUpdate(false);
        scanAgent.setUpdateOnly(false);
        scanAgent.setDependencies(dependencies);
        scanAgent.setProxyServer(Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_ADDRESS));
        scanAgent.setProxyPort(Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_PORT));
        scanAgent.setProxyUsername(Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_USERNAME));
        scanAgent.setProxyPassword(Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_PASSWORD));

        // If a global suppression file exists, use it.
        final File suppressions = new File(DC_GLOBAL_SUPPRESSION);
        if (suppressions.exists() && suppressions.isFile()) {
            scanAgent.setSuppressionFile(suppressions.getAbsolutePath());
        }

        try {
            scanAgent.execute();
        } catch (ScanAgentException ex) {
            LOGGER.error("An error occurred executing Dependency-Check scan agent: " + ex);
        }
        LOGGER.info("Dependency-Check analysis complete");
        processResults();
    }

    /**
     * Processes Dependency-Check results after the completion of a scan.
     */
    private void processResults() {
        LOGGER.info("Processing Dependency-Check analysis results");
        try (QueryManager qm = new QueryManager()) {
            final Analysis analysis = new DependencyCheckParser().parse(new File(DC_REPORT_FILE));
            for (org.owasp.dependencytrack.parser.dependencycheck.model.Dependency dependency : analysis.getDependencies()) {
                // Resolve internally stored component
                final Component component = qm.getObjectByUuid(Component.class, dependency.getFilePath());
                final org.owasp.dependencytrack.parser.dependencycheck.model.Dependency.Vulnerabilities vulnerabilities = dependency.getVulnerabilities();

                // Add vulnerability to an affected component
                if (vulnerabilities != null) {
                    for (org.owasp.dependencytrack.parser.dependencycheck.model.Vulnerability vulnerability : vulnerabilities.getVulnerabilities()) {
                        // Resolve internally stored vulnerability
                        Vulnerability internalVuln = qm.getVulnerabilityByVulnId(vulnerability.getSource(), vulnerability.getName());
                        if (internalVuln == null) {
                            // For some reason, the vulnerability discovered in the scan does not exist in the ODT database.
                            // This could be due to timing issue where the scan picked up a new vuln prior to ODT doing so,
                            // or it might be due to a ODC plugin that uses a vulnerability datasource that ODT does not support.
                            internalVuln = qm.createVulnerability(ModelConverter.convert(qm, vulnerability), true);
                        }
                        qm.addVulnerability(internalVuln, component);
                    }
                }

                // Remove vulnerability from an unaffected component - this could be due to false positive reduction
                // improvements in newer scanning engines, suppressions being asserted, or corrections made to the
                // vulnerability data source.
                if (component.getVulnerabilities() != null) {
                    for (Vulnerability internalVuln : component.getVulnerabilities()) {
                        boolean found = false;
                        for (org.owasp.dependencytrack.parser.dependencycheck.model.Vulnerability vulnerability : vulnerabilities
                                .getVulnerabilities()) {
                            if (internalVuln.getSource().equals(vulnerability.getSource()) && internalVuln.getVulnId()
                                    .equals(vulnerability.getName())) {
                                found = true;
                            }
                        }
                        if (!found) {
                            qm.removeVulnerability(internalVuln, component);
                        }
                    }
                }

            }
        } catch (ParseException e) {
            LOGGER.error("An error occurred while parsing Dependency-Check report", e);
        }
        LOGGER.info("Processing complete");
    }
}
