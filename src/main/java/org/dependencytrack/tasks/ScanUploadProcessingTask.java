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
package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import com.github.packageurl.PackageURL;
import org.dependencytrack.event.RepositoryMetaEvent;
import org.dependencytrack.event.ScanUploadEvent;
import org.dependencytrack.event.VulnerabilityAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Scan;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.dependencycheck.DependencyCheckParser;
import org.dependencytrack.parser.dependencycheck.model.Analysis;
import org.dependencytrack.parser.dependencycheck.model.Dependency;
import org.dependencytrack.parser.dependencycheck.model.Evidence;
import org.dependencytrack.parser.dependencycheck.resolver.ComponentGroupResolver;
import org.dependencytrack.parser.dependencycheck.resolver.ComponentNameResolver;
import org.dependencytrack.parser.dependencycheck.resolver.ComponentResolver;
import org.dependencytrack.parser.dependencycheck.resolver.ComponentVersionResolver;
import org.dependencytrack.parser.dependencycheck.resolver.LicenseResolver;
import org.dependencytrack.parser.dependencycheck.resolver.PackageURLResolver;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.CompressUtil;
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

    private Scan scan;
    private List<Component> components = new ArrayList<>();
    private QueryManager qm;

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof ScanUploadEvent) {
            final ScanUploadEvent event = (ScanUploadEvent) e;

            final File file = event.getFile();
            final byte[] scanData = CompressUtil.optionallyDecompress(event.getScan());
            try {
                final Analysis analysis = (file != null)
                        ? new DependencyCheckParser().parse(file)
                        : new DependencyCheckParser().parse(scanData);
                qm = new QueryManager();
                final Project project = qm.getObjectByUuid(Project.class, event.getProjectUuid());
                final Date date = new Date();
                scan = qm.createScan(project, analysis.getProjectInfo().getReportDate(), date);

                for (Dependency dependency : analysis.getDependencies()) {
                    processDependency(dependency);
                }

                qm.reconcileDependencies(project, components);
                qm.updateLastScanImport(project, date);

                Event.dispatch(new VulnerabilityAnalysisEvent(components).project(project));
            } catch (Exception ex) {
                LOGGER.error("Error while processing scan result", ex);
            } finally {
                if (qm != null) {
                    qm.commitSearchIndex(true, Component.class);
                    qm.close();
                }
            }
        }
    }

    private void processDependency(Dependency dependency) {
        // Attempt to resolve component
        final ComponentResolver componentResolver = new ComponentResolver(qm);
        Component component = componentResolver.resolve(dependency);

        // Attempt to resolve license
        final LicenseResolver licenseResolver = new LicenseResolver(qm);
        final License resolvedLicense = licenseResolver.resolve(dependency);

        if (component == null) {
            // Component could not be resolved (was null), so create a new component
            component = new Component();
            resolveMetadata(component, dependency, resolvedLicense);
            component = qm.createComponent(component, false);
            Event.dispatch(new RepositoryMetaEvent(component));
        } else {
            resolveMetadata(component, dependency, resolvedLicense);
            component = qm.updateComponent(component, false);
        }

        if (dependency.getVulnerabilities() != null && dependency.getVulnerabilities().getVulnerabilities() != null) {
            for (org.dependencytrack.parser.dependencycheck.model.Vulnerability dcvuln: dependency.getVulnerabilities().getVulnerabilities()) {

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
                final org.dependencytrack.model.Vulnerability dtvuln = qm.getVulnerabilityByVulnId(source, dcvuln.getName());
                if (dtvuln != null) {
                    qm.addVulnerability(dtvuln, component);
                }
            }
        }

        components.add(component);
        qm.bind(scan, component);

        if (dependency.getEvidenceCollected() != null) {
            for (Evidence evidence : dependency.getEvidenceCollected()) {
                qm.createEvidence(component, evidence.getType(), evidence.getConfidenceScore(evidence.getConfidenceType()), evidence
                        .getSource(), evidence.getName(), evidence.getValue());
            }
        }

        if (dependency.getRelatedDependencies() != null) {
            for (Dependency relatedDependency: dependency.getRelatedDependencies()) {
                processDependency(relatedDependency);
            }
        }
    }

    private void resolveMetadata(Component component, Dependency dependency, License resolvedLicense) {
        // Run PackageURL resolution and use that evidence to populate metadata
        final PackageURL purl = new PackageURLResolver().resolve(dependency);
        if (purl != null) {
            component.setGroup(purl.getNamespace());
            component.setName(purl.getName());
            component.setVersion(purl.getVersion());
            if (purl.getNamespace() == null) {
                component.setGroup(new ComponentGroupResolver().resolve(dependency));
            }
            // If a PackageURL could not be resolved, use the individual metadata resolvers.
        } else {
            component.setGroup(new ComponentGroupResolver().resolve(dependency));
            component.setName(new ComponentNameResolver().resolve(dependency));
            component.setVersion(new ComponentVersionResolver().resolve(dependency));
        }
        component.setPurl(purl);

        component.setFilename(dependency.getFileName());
        component.setMd5(dependency.getMd5());
        component.setSha1(dependency.getSha1());
        //todo: update this when ODC support other hash functions
        component.setDescription(dependency.getDescription());
        component.setResolvedLicense(resolvedLicense);
    }
}
