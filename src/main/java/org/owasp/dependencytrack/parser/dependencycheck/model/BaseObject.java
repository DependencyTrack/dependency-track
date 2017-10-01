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
package org.owasp.dependencytrack.parser.dependencycheck.model;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.dependency.Confidence;

/**
 * Defines a base object that provides helper methods used to
 * determine confidence of evidence used in identifying components.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public abstract class BaseObject {

    protected String normalize(String string) {
        return StringUtils.normalizeSpace(StringUtils.trimToNull(string));
    }

    protected Confidence getConfidenceFromString(String confidence) {
        switch (normalize(confidence)) {
            case "HIGHEST":
                return Confidence.HIGHEST;
            case "HIGH":
                return Confidence.HIGH;
            case "MEDIUM":
                return Confidence.MEDIUM;
            case "LOW":
                return Confidence.LOW;
            default:
                return Confidence.LOW;
        }
    }

    public int getConfidenceScore(Confidence confidence) {
        switch (confidence.name()) {
            case "HIGHEST":
                return 4;
            case "HIGH":
                return 3;
            case "MEDIUM":
                return 2;
            case "LOW":
                return 1;
            default:
                return 1;
        }
    }

}

