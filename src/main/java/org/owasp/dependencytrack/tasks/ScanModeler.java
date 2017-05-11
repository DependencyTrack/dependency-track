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

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import org.owasp.dependencytrack.event.ScanUploadEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Cwe;
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
import us.springett.cvss.CvssV2;
import us.springett.cvss.Score;
import java.io.File;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class ScanModeler implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ScanModeler.class);

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
                final Scan scan = qm.createScan(project, analysis.getProjectInfo().getReportDate(), new Date());

                final List<Component> components = new ArrayList<>();
                for (Dependency dependency : analysis.getDependencies()) {

                    // Attempt to resolve component
                    final ComponentResolver componentResolver = new ComponentResolver();
                    Component component = componentResolver.resolve(dependency);

                    // Attempt to resolve license
                    final LicenseResolver licenseResolver = new LicenseResolver();
                    final License resolvedLicense = licenseResolver.resolve(dependency);

                    if (component == null) {
                        // Component could not be resolved (was null), so create a new component
                        component = qm.createComponent(
                                new ComponentNameResolver().resolve(dependency),
                                new ComponentVersionResolver().resolve(dependency),
                                new ComponentGroupResolver().resolve(dependency),
                                dependency.getFileName(),
                                dependency.getMd5(),
                                dependency.getSha1(),
                                dependency.getDescription(),
                                resolvedLicense,
                                dependency.getLicense(),
                                null
                        );
                    }

                    qm.createDependencyIfNotExist(project, component, null, null);

                    if (dependency.getVulnerabilities() != null && dependency.getVulnerabilities().getVulnerabilities() != null) {
                        for (org.owasp.dependencytrack.parser.dependencycheck.model.Vulnerability dcvuln: dependency.getVulnerabilities().getVulnerabilities()) {
                            //first - check if vuln already exists...
                            org.owasp.dependencytrack.model.Vulnerability dtvuln = qm.getVulnerabilityByVulnId(dcvuln.getName());
                            if (dtvuln == null) { // Vuln doesn't exist - create it
                                Cwe cwe = null;
                                // Lookup CWE (if exists in report)
                                if (dcvuln.getCwe() != null) {
                                    final int cweId = Integer.parseInt(dcvuln.getCwe().substring(4, 7).trim());
                                    cwe = qm.getCweById(cweId);
                                }

                                // Re-scoring in order to obtain impact and exploitable sub scores not present in the NVD feed.
                                final String av = normalize(dcvuln.getCvssAccessVector());
                                final String ac = normalize(dcvuln.getCvssAccessComplexity());
                                final String au = normalize(dcvuln.getCvssAuthenticationr());
                                final String c = normalize(dcvuln.getCvssConfidentialImpact());
                                final String i = normalize(dcvuln.getCvssIntegrityImpact());
                                final String a = normalize(dcvuln.getCvssAvailabilityImpact());

                                BigDecimal v2BaseScore = null;
                                BigDecimal v2ImpactSubScore = null;
                                BigDecimal v2ExploitSubScore = null;
                                String v2Vector = null;

                                if (av != null && ac != null && au != null && c != null && i != null && a != null) {
                                    final CvssV2 cvssV2 = new CvssV2()
                                            .attackVector(CvssV2.AttackVector.valueOf(av))
                                            .attackComplexity(CvssV2.AttackComplexity.valueOf(ac))
                                            .authentication(CvssV2.Authentication.valueOf(au))
                                            .confidentiality(CvssV2.CIA.valueOf(c))
                                            .integrity(CvssV2.CIA.valueOf(i))
                                            .availability(CvssV2.CIA.valueOf(a));

                                    final Score score = cvssV2.calculateScore();
                                    v2BaseScore = new BigDecimal(score.getBaseScore());
                                    v2ImpactSubScore = new BigDecimal(score.getImpactSubScore());
                                    v2ExploitSubScore = new BigDecimal(score.getExploitabilitySubScore());
                                    v2Vector = cvssV2.getVector();
                                }

                                dtvuln = qm.createVulnerability(dcvuln.getName(), dcvuln.getDescription(),
                                        Vulnerability.Source.NVD, cwe,
                                        v2BaseScore, v2ImpactSubScore, v2ExploitSubScore, v2Vector,
                                        null, null, null, null,
                                        null, null);
                                qm.bind(component, dtvuln);
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
            } catch (Exception ex) {
                LOGGER.error("Error while processing scan result");
                LOGGER.error(ex.getMessage());
            } finally {
                if (qm != null) {
                    qm.close();
                }
            }
        }
    }

    private String normalize(String in) {
        switch (in) {
            case ("SINGLE_INSTANCE")    : return "SINGLE";
            case ("MULTIPLE_INSTANCES") : return "MULTIPLE";
            case ("NONE")               : return "NONE";
            case ("LOW")                : return "LOW";
            case ("MEDIUM")             : return "MEDIUM";
            case ("HIGH")               : return "HIGH";
            case ("PARTIAL")            : return "PARTIAL";
            case ("COMPLETE")           : return "COMPLETE";
            case ("LOCAL")              : return "LOCAL";
            case ("ADJACENT")           : return "ADJACENT";
            case ("NETWORK")            : return "NETWORK";
            case ("PHYSICAL")           : return "PHYSICAL";
            default                     : return null;
        }
    }
}
