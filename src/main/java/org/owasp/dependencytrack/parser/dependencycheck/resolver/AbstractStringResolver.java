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
 * This class will resolve string-based evidence.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public abstract class AbstractStringResolver {

    /**
     * Attempts to resolve the most likely to be accurate evidence.
     * @param dependency the Dependency to extract evidence from
     * @param evidenceType the type of evidence to extract (typically: product, vendor, version)
     * @param minConfidenceScore the minimum confidence score
     * @return the highly confidence evidence, or null if not found or doesn't meet criteria
     */
    protected String resolve(Dependency dependency, String evidenceType, int minConfidenceScore) {
        Evidence best = null;
        final List<Evidence> evidenceList = dependency.getEvidenceCollected();
        for (Evidence evidence: evidenceList) {
            // do not trust configure.in - all kinds of irrelevant stuff in there
            if (evidenceType.equals(evidence.getType()) && !("configure.in".equals(evidence.getSource()))) {
                if (best == null || (evidence.getConfidenceScore() > best.getConfidenceScore())) {
                    if (evidence.getConfidenceScore() >= minConfidenceScore) {
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
