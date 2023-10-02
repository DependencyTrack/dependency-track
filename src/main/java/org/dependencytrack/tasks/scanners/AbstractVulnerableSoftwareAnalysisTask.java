/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.scanners;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.ComponentVersion;
import org.dependencytrack.util.NotificationUtil;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.values.LogicalValue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

/**
 * Base analysis task for using the internal VulnerableSoftware model as the source of truth for
 * vulnerability intelligence.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public abstract class AbstractVulnerableSoftwareAnalysisTask extends BaseComponentAnalyzerTask {

    /**
     * Analyzes the targetVersion against a list of VulnerableSoftware objects which may contain
     * specific versions or version ranges. For every match, every vulnerability associated with
     * the VulnerableSoftware object will be applied to the specified component.
     *
     * @param qm the QueryManager to use
     * @param vsList a list of VulnerableSoftware objects
     * @param targetVersion the version of the component
     * @param component the component being analyzed
     */
    protected void analyzeVersionRange(final QueryManager qm, final List<VulnerableSoftware> vsList,
                                       final String targetVersion, final String targetUpdate, final Component component,
                                       final VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel) {
        for (final VulnerableSoftware vs: vsList) {
            if (compareVersions(vs, targetVersion) && compareUpdate(vs, targetUpdate)) {
                if (vs.getVulnerabilities() != null) {
                    for (final Vulnerability vulnerability : vs.getVulnerabilities()) {
                        NotificationUtil.analyzeNotificationCriteria(qm, vulnerability, component, vulnerabilityAnalysisLevel);
                        qm.addVulnerability(vulnerability, component, this.getAnalyzerIdentity());
                    }
                }
            }
        }
    }

    /**
     * Evaluates the target against the version and version range checks:
     * versionEndExcluding, versionStartExcluding versionEndIncluding, and
     * versionStartIncluding.
     *
     * @param vs a reference to the vulnerable software to compare
     * @param targetVersion the version to compare
     * @return <code>true</code> if the target version is matched; otherwise
     * <code>false</code>
     *
     * Ported from Dependency-Check v5.2.1
     */
    private static boolean compareVersions(VulnerableSoftware vs, String targetVersion) {
        // For VulnerableSoftware (could actually be hardware) without a version number.
        // e.g. cpe:2.3:o:intel:2000e_firmware:-:*:*:*:*:*:*:*
        if (LogicalValue.NA.getAbbreviation().equals(vs.getVersion())) {
            return true;
        }
        //if any of the four conditions will be evaluated - then true;
        boolean result = (vs.getVersionEndExcluding() != null && !vs.getVersionEndExcluding().isEmpty())
                || (vs.getVersionStartExcluding() != null && !vs.getVersionStartExcluding().isEmpty())
                || (vs.getVersionEndIncluding() != null && !vs.getVersionEndIncluding().isEmpty())
                || (vs.getVersionStartIncluding() != null && !vs.getVersionStartIncluding().isEmpty());

        // Modified from original by Steve Springett
        // Added null check: vs.getVersion() != null as purl sources that use version ranges may not have version populated.
        if (!result && vs.getVersion() != null && compareAttributes(vs.getVersion(), targetVersion)) {
            return true;
        }

        final ComponentVersion target = new ComponentVersion(targetVersion);
        if (target.getVersionParts().isEmpty()) {
            return false;
        }
        if (result && vs.getVersionEndExcluding() != null && !vs.getVersionEndExcluding().isEmpty()) {
            final ComponentVersion endExcluding = new ComponentVersion(vs.getVersionEndExcluding());
            result = endExcluding.compareTo(target) > 0;
        }
        if (result && vs.getVersionStartExcluding() != null && !vs.getVersionStartExcluding().isEmpty()) {
            final ComponentVersion startExcluding = new ComponentVersion(vs.getVersionStartExcluding());
            result = startExcluding.compareTo(target) < 0;
        }
        if (result && vs.getVersionEndIncluding() != null && !vs.getVersionEndIncluding().isEmpty()) {
            final ComponentVersion endIncluding = new ComponentVersion(vs.getVersionEndIncluding());
            result &= endIncluding.compareTo(target) >= 0;
        }
        if (result && vs.getVersionStartIncluding() != null && !vs.getVersionStartIncluding().isEmpty()) {
            final ComponentVersion startIncluding = new ComponentVersion(vs.getVersionStartIncluding());
            result &= startIncluding.compareTo(target) <= 0;
        }
        return result;
    }

    private static final Method COMPARE_ATTRIBUTES_METHOD;

    static {
        try {
            // Workaround for the fact that Cpe#compareAttributes has protected visibility.
            COMPARE_ATTRIBUTES_METHOD = Cpe.class.getDeclaredMethod("compareAttributes", String.class, String.class);
            COMPARE_ATTRIBUTES_METHOD.setAccessible(true);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException("Failed to access compareAttributes method of %s".formatted(Cpe.class.getName()), e);
        }
    }

    private static boolean compareAttributes(String left, String right) {
        try {
            return (Boolean) COMPARE_ATTRIBUTES_METHOD.invoke(null, left, right);
        } catch (InvocationTargetException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Evaluates the target update against the vulnerable software. The update
     * field is optional and if the value is ANY (*), then it will return true.
     * Otherwise, the updates are compared against each other.

     * @param vs a reference to the vulnerable software to compare
     * @param targetUpdate the update to compare
     * @return <code>true</code> if the target update is matched; otherwise
     * <code>false</code>
     */
    private static boolean compareUpdate(VulnerableSoftware vs, String targetUpdate) {

        if (targetUpdate != null && targetUpdate.equals(vs.getUpdate())) {
            return true;
        }
        if (LogicalValue.NA.getAbbreviation().equals(vs.getUpdate())) {
            return false;
        }
        if (vs.getUpdate() == null && targetUpdate == null) {
            return true;
        }
        // Moving this above the null OR check to reflect method comments (ANY should mean ANY)
        // This is necessary for fuzz matching when a PURL which assumes null
        // is matched to a CPE which defaults to ANY
        if (LogicalValue.ANY.getAbbreviation().equals(targetUpdate) || LogicalValue.ANY.getAbbreviation().equals(vs.getUpdate())) {
            return true;
        }
        if (vs.getUpdate() == null || targetUpdate == null) {
            return false;
        }
        return compareAttributes(vs.getUpdate(), targetUpdate);
    }
}
