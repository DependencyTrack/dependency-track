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
package org.owasp.dependencytrack.parser.dependencycheck.resolver;

import org.owasp.dependencytrack.parser.dependencycheck.model.Dependency;
import org.owasp.dependencytrack.parser.dependencycheck.model.Evidence;
import java.util.List;

/**
 * Attempts to resolve the version of the component from evidence
 * available in the specified dependency.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class ComponentVersionResolver implements IResolver {

    /**
     * {@inheritDoc}
     */
    public String resolve(Dependency dependency) {
        Evidence best = null;
        final List<Evidence> evidenceList = dependency.getEvidenceCollected();
        for (Evidence evidence: evidenceList) {
            // do not trust configure.in - all kinds of irrelevant stuff in there
            if ("version".equals(evidence.getType()) && !("configure.in".equals(evidence.getSource()))) {
                if ("file".equals(evidence.getSource()) && "HIGHEST".equals(evidence.getConfidence())) {
                    return evidence.getValue();
                }
                if (best == null || (evidence.getConfidenceScore() > best.getConfidenceScore())) {
                    if (evidence.getConfidenceScore() >= 2) { // We only want MEDIUM, HIGH or HIGHEST
                        best = evidence;
                    }
                }
            }
        }
        if (best != null) {
            return best.getValue();
        }
        return null;
    }
}
