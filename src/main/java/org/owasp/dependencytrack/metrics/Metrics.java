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
package org.owasp.dependencytrack.metrics;

/**
 * Helper class for enhancing metrics.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public final class Metrics {

    private Metrics() { }

    public static double inheritedRiskScore(int high, int medium, int low) {
        return inheritedRiskScore(0, high, medium, low);
    }

    public static double inheritedRiskScore(int critical, int high, int medium, int low) {
        return (double) ((critical * 10) + (high * 5) + (medium * 3) + (low * 1));
    }

    public static double vulnerableComponentRatio(int vulnerabilities, int vulnerableComponents) {
        double ratio = 0.0;
        if (vulnerableComponents > 0) {
            ratio = (double) vulnerabilities / vulnerableComponents;
        }
        return ratio;
    }
}
