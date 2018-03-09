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

import alpine.event.framework.Event;
import alpine.event.framework.SingleThreadedEventService;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import org.owasp.dependencytrack.event.DependencyCheckEvent;
import org.owasp.dependencytrack.event.ScanUploadEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.Scan;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.parser.dependencycheck.DependencyCheckParser;
import org.owasp.dependencytrack.parser.dependencycheck.model.Analysis;
import org.owasp.dependencytrack.parser.dependencycheck.model.Dependency;
import org.owasp.dependencytrack.parser.dependencycheck.model.Evidence;
import org.owasp.dependencytrack.parser.dependencycheck.resolver.ComponentGroupResolver;
import org.owasp.dependencytrack.parser.dependencycheck.resolver.ComponentNameResolver;
import org.owasp.dependencytrack.parser.dependencycheck.resolver.ComponentResolver;
import org.owasp.dependencytrack.parser.dependencycheck.resolver.ComponentVersionResolver;
import org.owasp.dependencytrack.parser.dependencycheck.resolver.LicenseResolver;
import org.owasp.dependencytrack.persistence.QueryManager;
import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Subscriber task that performs processing of a Dependency-Check scan
 * when it is uploaded.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ScanUploadProcessingTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ScanUploadProcessingTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof ScanUploadEvent) {
            final ScanUploadEvent event = (ScanUploadEvent) e;

            final File file = event.getFile();
            final byte[] scanData = event.getScan();
            QueryManager qm = null;
            try {
                final Analysis analysis = (file != null)
                        ? new DependencyCheckParser().parse(file)
                        : new DependencyCheckParser().parse(scanData);
                qm = new QueryManager();
                final Project project = qm.getObjectByUuid(Project.class, event.getProjectUuid());
                final Date date = new Date();
                final Scan scan = qm.createScan(project, analysis.getProjectInfo().getReportDate(), date);

                final List<Component> components = new ArrayList<>();
                for (Dependency dependency : analysis.getDependencies()) {

                    // Attempt to resolve component
                    final ComponentResolver componentResolver = new ComponentResolver(qm);
                    Component component = componentResolver.resolve(dependency);

                    // Attempt to resolve license
                    final LicenseResolver licenseResolver = new LicenseResolver(qm);
                    final License resolvedLicense = licenseResolver.resolve(dependency);

                    if (component == null) {
                        // Component could not be resolved (was null), so create a new component
                        component = new Component();
                        component.setName(new ComponentNameResolver().resolve(dependency));
                        component.setVersion(new ComponentVersionResolver().resolve(dependency));
                        component.setGroup(new ComponentGroupResolver().resolve(dependency));
                        component.setFilename(dependency.getFileName());
                        component.setMd5(dependency.getMd5());
                        component.setSha1(dependency.getSha1());
                        //todo: update this when ODC support other hash functions
                        component.setDescription(dependency.getDescription());
                        component.setResolvedLicense(resolvedLicense);
                        component = qm.createComponent(component, false);
                    } else {
                        /*
                         * Account for improvements in evidence identification in ODC and resolution improvements in ODT.
                         * In cases where values are null, attempt to re-populate specific fields with the same values
                         * as they would be if the component was newly created.
                         *
                         * In the future, it may be desirable to distinguish between user-corrected data and native data.
                         * (i.e.: component.getName()  vs.  component.getNameCorrected()
                         * //todo: Determine if this is necessary
                         */
                        component.setName((component.getName() != null) ? component.getName() : new ComponentNameResolver().resolve(dependency));
                        component.setVersion((component.getVersion() != null) ? component.getVersion() : new ComponentVersionResolver().resolve(dependency));
                        component.setGroup((component.getGroup() != null) ? component.getGroup() : new ComponentGroupResolver().resolve(dependency));
                        component.setFilename((component.getFilename() != null) ? component.getFilename() : dependency.getFileName());
                        component.setDescription((component.getDescription() != null) ? component.getDescription() : dependency.getDescription());
                        if (component.getResolvedLicense() == null) {
                            component.setResolvedLicense(resolvedLicense);
                        }
                        component = qm.updateComponent(component, false);
                    }

                    qm.createDependencyIfNotExist(project, component, null, null);

                    if (dependency.getVulnerabilities() != null && dependency.getVulnerabilities().getVulnerabilities() != null) {
                        for (org.owasp.dependencytrack.parser.dependencycheck.model.Vulnerability dcvuln: dependency.getVulnerabilities().getVulnerabilities()) {

                            /*
                             * Resolve the source of the vulnerability. The source as defined in ODC needs to be
                             * the same as the source identified in ODT. Defaults to NVD since older versions of
                             * ODC did not support the 'source' attribute and only used the NVD.
                             */
                            Vulnerability.Source source = Vulnerability.Source.NVD;
                            if (dcvuln.getSource() != null) {
                                source = Vulnerability.Source.valueOf(dcvuln.getSource().toUpperCase());
                            }

                            /*
                             * Check to see if the vulnerability already exists. If so, bind it to the component.
                             */
                            final org.owasp.dependencytrack.model.Vulnerability dtvuln = qm.getVulnerabilityByVulnId(source.name(), dcvuln.getName());
                            if (dtvuln != null) {
                                qm.addVulnerability(dtvuln, component);
                            }
                        }
                    }

                    components.add(component);
                    qm.bind(scan, component);

                    for (Evidence evidence : dependency.getEvidenceCollected()) {
                        qm.createEvidence(component, evidence.getType(), evidence.getConfidenceScore(evidence.getConfidenceType()), evidence
                                .getSource(), evidence.getName(), evidence.getValue());
                    }
                }
                qm.updateLastScanImport(project, date);
                SingleThreadedEventService.getInstance().publish(new DependencyCheckEvent(components));
            } catch (Exception ex) {
                LOGGER.error("Error while processing scan result");
                LOGGER.error(ex.getMessage());
            } finally {
                if (qm != null) {
                    qm.commitSearchIndex(true, Component.class);
                    qm.close();
                }
            }
        }
    }
}
