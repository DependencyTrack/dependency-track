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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.componentanalysis;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao;
import org.dependencytrack.persistence.jdbi.ComponentAnalysisDao.ComponentAnalysis;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * Re-applies durable component analyses (license curation) onto a project's
 * components during BOM ingest.
 * <p>
 * BOM ingest overwrites component license fields with whatever the uploaded
 * BOM declares; analyses are identity-keyed records that survive uploads and
 * are re-applied here on every ingest — after the BOM's own license
 * resolution and before policy evaluation, so LICENSE policy violations are
 * evaluated against the curated license.
 */
public final class ComponentAnalysisApplier {

    private static final Logger LOGGER = LoggerFactory.getLogger(ComponentAnalysisApplier.class);

    private final QueryManager qm;
    private final Map<IdentityKey, ComponentAnalysis> analysesByIdentity;
    private final Map<Long, License> licenseCache = new HashMap<>();
    private int appliedCount;

    private ComponentAnalysisApplier(final QueryManager qm, final Map<IdentityKey, ComponentAnalysis> analysesByIdentity) {
        this.qm = qm;
        this.analysesByIdentity = analysesByIdentity;
    }

    public static ComponentAnalysisApplier forProject(final QueryManager qm, final long projectId) {
        final List<ComponentAnalysis> analyses = withJdbiHandle(
                handle -> new ComponentAnalysisDao(handle).getAllByProject(projectId));
        return new ComponentAnalysisApplier(qm, analyses.stream()
                .collect(Collectors.toMap(
                        analysis -> new IdentityKey(analysis.purl(), analysis.group(), analysis.name(), analysis.version()),
                        Function.identity(),
                        (previous, duplicate) -> previous)));
    }

    /**
     * Applies the component's analysis, if one exists. Must be called on the
     * persistent component AFTER field synchronization from the BOM — the
     * override must win over the BOM-declared license.
     */
    public void apply(final Component component) {
        if (analysesByIdentity.isEmpty()) {
            return;
        }
        final ComponentAnalysis analysis = analysesByIdentity.get(new IdentityKey(
                component.getPurl() != null ? component.getPurl().canonicalize() : null,
                component.getGroup(), component.getName(), component.getVersion()));
        if (analysis == null) {
            return;
        }
        if (analysis.licenseId() != null) {
            final License license = licenseCache.computeIfAbsent(
                    analysis.licenseId(), id -> qm.getObjectById(License.class, id));
            if (license != null) {
                // refresh the declared snapshot from what this upload brought,
                // BEFORE overriding — clearing the override restores it
                withJdbiHandle(handle -> {
                    new ComponentAnalysisDao(handle).updateDeclaredSnapshot(
                            analysis.id(),
                            component.getResolvedLicense() != null
                                    ? component.getResolvedLicense().getId() : null,
                            component.getLicense(),
                            component.getLicenseExpression());
                    return null;
                });
                component.setResolvedLicense(license);
                component.setLicenseExpression(null);
            } else {
                LOGGER.warn("Component analysis {} references a license that no longer exists; skipping license override", analysis.id());
            }
        }
        if (analysis.details() != null) {
            component.setNotes(analysis.details());
        }
        appliedCount++;
    }

    public int appliedCount() {
        return appliedCount;
    }

    /**
     * Identity used for matching, null-normalized so it behaves identically
     * to the COALESCE-based unique index on COMPONENT_ANALYSIS.
     */
    private record IdentityKey(String purl, String group, String name, String version) {
        private IdentityKey {
            purl = Objects.requireNonNullElse(purl, "");
            group = Objects.requireNonNullElse(group, "");
            name = Objects.requireNonNullElse(name, "");
            version = Objects.requireNonNullElse(version, "");
        }
    }
}
