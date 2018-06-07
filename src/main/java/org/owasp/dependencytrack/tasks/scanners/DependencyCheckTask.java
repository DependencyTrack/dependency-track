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
package org.owasp.dependencytrack.tasks.scanners;

import alpine.Config;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import com.github.packageurl.PackageURL;
import org.owasp.dependencycheck.agent.DependencyCheckScanAgent;
import org.owasp.dependencycheck.exception.ScanAgentException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencytrack.event.DependencyCheckEvent;
import org.owasp.dependencytrack.event.MetricsUpdateEvent;
import org.owasp.dependencytrack.exception.ParseException;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.parser.dependencycheck.DependencyCheckParser;
import org.owasp.dependencytrack.parser.dependencycheck.model.Analysis;
import org.owasp.dependencytrack.parser.dependencycheck.util.ModelConverter;
import org.owasp.dependencytrack.persistence.QueryManager;
import org.owasp.dependencytrack.util.HttpClientFactory;
import java.io.File;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;

import static org.owasp.dependencytrack.tasks.NistMirrorTask.NVD_MIRROR_DIR;

/**
 * Subscriber task that performs a Dependency-Check analysis or update.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class DependencyCheckTask extends BaseComponentAnalyzerTask implements ScanTask, Subscriber {

    private static final Logger LOGGER = Logger.getLogger(DependencyCheckTask.class);
    private static final String DC_ROOT_DIR = Config.getInstance().getDataDirectorty().getAbsolutePath() + File.separator + "dependency-check";
    private static final String DC_DATA_DIR = DC_ROOT_DIR + File.separator + "data";
    private static final String DC_REPORT_DIR = DC_ROOT_DIR + File.separator + "reports";
    private static final String DC_REPORT_FILE = DC_REPORT_DIR + File.separator + "dependency-check-report.xml";
    private static final String DC_GLOBAL_PROPERTIES = DC_ROOT_DIR + File.separator + "dependency-check.properties";
    private static final String DC_GLOBAL_SUPPRESSION = DC_ROOT_DIR + File.separator + "suppressions.xml";

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof DependencyCheckEvent) {
            setupOdcDirectoryStructure(DC_ROOT_DIR);
            setupOdcDirectoryStructure(DC_DATA_DIR);
            setupOdcDirectoryStructure(DC_REPORT_DIR);
            final DependencyCheckEvent event = (DependencyCheckEvent) e;
            if (DependencyCheckEvent.Action.ANALYZE == event.getAction()) {
                if (event.getComponents().size() > 0) {
                    analyze(event.getComponents());
                } else {
                    super.analyze();
                }
            } else if (DependencyCheckEvent.Action.UPDATE_ONLY == event.getAction()) {
                performUpdateOnly();
            }
        }
    }

    /**
     * Ensures the Dependency-Check directory structure exists.
     */
    private void setupOdcDirectoryStructure(String directory) {
        File dir = new File(directory);
        if (!dir.exists()) {
            if (dir.mkdirs()) {
                LOGGER.info("Dependency-Check directory created successfully: " + directory);
            }
        }
    }

    /**
     * Performs an update of the Dependency-Check data directory only.
     */
    private void performUpdateOnly() {
        LOGGER.info("Executing Dependency-Check update-only task");
        DependencyCheckScanAgent scanAgent = createScanAgent(true);
        try {
            scanAgent.execute();
        } catch (ScanAgentException ex) {
            LOGGER.error("An error occurred executing Dependency-Check scan agent", ex);
        }
        LOGGER.info("Dependency-Check update-only complete");
    }

    /**
     * Analyzes a list of Components.
     * @param components a list of Components
     */
    public void analyze(List<Component> components) {
        LOGGER.info("Executing Dependency-Check analysis task");
        // Iterate through the components, create evidence, and create the resulting dependency
        final List<org.owasp.dependencycheck.dependency.Dependency> dependencies = new ArrayList<>();
        for (Component component: components) {

            // Check to see that Dependency-Check only analyzes ecosystems
            // and uses analyzers capable of supporting Dependency-Track
            PackageURL purl = component.getPurl();
            if (super.shouldAnalyze(purl)) {
                dependencies.add(ModelConverter.convert(component));
            }

        }
        LOGGER.info("Analyzing " + dependencies.size() + " component(s)");
        DependencyCheckScanAgent scanAgent = createScanAgent(false);
        scanAgent.setDependencies(dependencies);

        // If a global properties file exists, use it.
        final File properties = new File(DC_GLOBAL_PROPERTIES);
        if (properties.exists() && properties.isFile()) {
            scanAgent.setPropertiesFilePath(properties.getAbsolutePath());
        }

        // If a global suppression file exists, use it.
        final File suppressions = new File(DC_GLOBAL_SUPPRESSION);
        if (suppressions.exists() && suppressions.isFile()) {
            scanAgent.setSuppressionFile(suppressions.getAbsolutePath());
        }

        try {
            scanAgent.execute();
            processResults();
            LOGGER.info("Dependency-Check analysis complete");
        } catch (ScanAgentException ex) {
            LOGGER.error("An error occurred executing Dependency-Check scan agent", ex);
        }
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
                // The dependency filePath contains the UUID and the filename of the component - Specified in ModelConverter
                int separator = dependency.getFilePath().indexOf(File.separator);
                if (separator != 36) {
                    LOGGER.warn("Component cannot be resolved. Missing file separator or invalid component UUID.");
                    continue;
                }
                String uuid = dependency.getFilePath().substring(0, separator);
                final Component component = qm.getObjectByUuid(Component.class, uuid);
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

                /* todo: put this logic back in once NSP support is complete #106 -- also account for INTERNAL vulnerabilities
                if (component.getVulnerabilities() != null) {
                    for (Vulnerability internalVuln : component.getVulnerabilities()) {
                        boolean found = false;
                        if (vulnerabilities != null) {
                            for (org.owasp.dependencytrack.parser.dependencycheck.model.Vulnerability vulnerability : vulnerabilities
                                    .getVulnerabilities()) {
                                if (internalVuln.getSource().equals(vulnerability.getSource()) && internalVuln.getVulnId()
                                        .equals(vulnerability.getName())) {
                                    found = true;
                                }
                            }
                        }
                        if (!found) {
                            qm.removeVulnerability(internalVuln, component);
                        }
                    }
                }
                */

                Event.dispatch(new MetricsUpdateEvent(component));

            }
        } catch (ParseException e) {
            LOGGER.error("An error occurred while parsing Dependency-Check report", e);
        }
        LOGGER.info("Processing complete");
    }

    private DependencyCheckScanAgent createScanAgent(boolean update) {
        final DependencyCheckScanAgent scanAgent = new DependencyCheckScanAgent();
        scanAgent.setDataDirectory(DC_DATA_DIR);
        scanAgent.setReportOutputDirectory(DC_REPORT_DIR);
        scanAgent.setReportFormat(ReportGenerator.Format.XML);
        scanAgent.setAutoUpdate(true);
        scanAgent.setUpdateOnly(update);
        //scanAgent.setCpeStartsWithFilter("cpe:"); //todo: will be available in 3.1.1

        HttpClientFactory.ProxyInfo proxyInfo = HttpClientFactory.createProxyInfo();
        if (proxyInfo != null) {
            scanAgent.setProxyServer(proxyInfo.getHost());
            scanAgent.setProxyPort(String.valueOf(proxyInfo.getPort()));
            scanAgent.setProxyUsername(proxyInfo.getUsername());
            scanAgent.setProxyPassword(proxyInfo.getPassword());
        }
        try {
            scanAgent.setCveUrl12Base(new File(NVD_MIRROR_DIR + File.separator).toURI().toURL().toExternalForm() + "nvdcve-%d.xml.gz");
            scanAgent.setCveUrl20Base(new File(NVD_MIRROR_DIR + File.separator).toURI().toURL().toExternalForm() + "nvdcve-2.0-%d.xml.gz");
            scanAgent.setCveUrl12Modified(new File(NVD_MIRROR_DIR + File.separator).toURI().toURL().toExternalForm() + "nvdcve-Modified.xml.gz");
            scanAgent.setCveUrl20Modified(new File(NVD_MIRROR_DIR + File.separator).toURI().toURL().toExternalForm() + "nvdcve-2.0-Modified.xml.gz");
        } catch (MalformedURLException e) {
            LOGGER.error("The local file URL Dependency-Check is using to retrieve the NVD mirrored contents is invalid", e);
        }
        return scanAgent;
    }
}
