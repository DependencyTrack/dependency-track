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
package org.owasp.dependencytrack.event.subscribers;

import org.owasp.dependencytrack.event.ScanUploadEvent;
import org.owasp.dependencytrack.event.framework.Event;
import org.owasp.dependencytrack.event.framework.Subscriber;
import org.owasp.dependencytrack.exception.ParseException;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.Scan;
import org.owasp.dependencytrack.parser.dependencycheck.DependencyCheckParser;
import org.owasp.dependencytrack.parser.dependencycheck.model.Analysis;
import org.owasp.dependencytrack.parser.dependencycheck.model.Dependency;
import org.owasp.dependencytrack.parser.dependencycheck.model.Evidence;
import org.owasp.dependencytrack.persistence.QueryManager;
import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class ScanModeler implements Subscriber {

    public void inform(Event event) {
        if (event instanceof ScanUploadEvent) {

            File file = ((ScanUploadEvent)event).getFile();
            try {
                Analysis analysis = new DependencyCheckParser().parse(file);

                QueryManager qm = new QueryManager();
                Project project = qm.createProject(analysis.getProjectInfo().getName());
                Scan scan = qm.createScan(project, new Date(), new Date());

                List<Component> components = new ArrayList<>();
                for (Dependency dependency : analysis.getDependencies()) {
                    Component component = qm.createComponent(
                            dependency.getFileName(),
                            dependency.getFileName(),
                            dependency.getMd5(),
                            dependency.getSha1(),
                            dependency.getDescription(),
                            dependency.getLicense(),
                            null
                    );
                    components.add(component);
                    qm.bind(scan, component);

                    for (Evidence evidence : dependency.getEvidenceCollected()) {
                        qm.createEvidence(component, evidence.getType(), evidence.getConfidenceScore(evidence.getConfidenceType()), evidence
                                .getSource(), evidence.getName(), evidence.getValue());
                    }
                }

                qm.close();
            } catch (ParseException e) {

            }
        }
    }
}
