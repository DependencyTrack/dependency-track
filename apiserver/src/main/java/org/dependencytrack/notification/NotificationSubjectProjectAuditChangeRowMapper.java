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
package org.dependencytrack.notification;

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.model.AppliedPolicyAnnotation;
import org.dependencytrack.notification.proto.v1.Component;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.Vulnerability;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysis;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.persistence.converter.PolicyAnnotationsJsonConverter;
import org.jdbi.v3.core.mapper.RowViewMapper;
import org.jdbi.v3.core.result.RowView;

import java.util.List;

final class NotificationSubjectProjectAuditChangeRowMapper
        implements RowViewMapper<VulnerabilityAnalysisDecisionChangeSubject> {

    @Override
    public VulnerabilityAnalysisDecisionChangeSubject map(RowView rowView) {
        final Component component = rowView.getRow(Component.class);
        final Project project = rowView.getRow(Project.class);
        final Vulnerability vuln = rowView.getRow(Vulnerability.class);
        final VulnerabilityAnalysis.Builder analysisBuilder = VulnerabilityAnalysis.newBuilder()
                .setComponent(component)
                .setProject(project)
                .setVulnerability(vuln)
                .setState(rowView.getColumn("vulnAnalysisState", String.class))
                .setSuppressed(rowView.getColumn("isVulnAnalysisSuppressed", Boolean.class));
        final String policyAnnotationsJson = rowView.getColumn("policyAnnotationsJson", String.class);
        if (policyAnnotationsJson != null) {
            final List<AppliedPolicyAnnotation> annotations =
                    new PolicyAnnotationsJsonConverter().convertToAttribute(policyAnnotationsJson);
            for (final AppliedPolicyAnnotation annotation : annotations) {
                final org.dependencytrack.notification.proto.v1.AppliedPolicyAnnotation.Builder annotationBuilder =
                        org.dependencytrack.notification.proto.v1.AppliedPolicyAnnotation.newBuilder()
                                .setPolicyName(annotation.policyName());
                if (annotation.appliedAt() != null) {
                    annotationBuilder.setAppliedAt(
                            Timestamps.fromMillis(annotation.appliedAt().getTime()));
                }
                if (annotation.annotator() != null) {
                    annotationBuilder.setAnnotator(annotation.annotator());
                }
                analysisBuilder.addPolicyAnnotations(annotationBuilder);
            }
        }
        return VulnerabilityAnalysisDecisionChangeSubject.newBuilder()
                .setComponent(component)
                .setProject(project)
                .setVulnerability(vuln)
                .setAnalysis(analysisBuilder)
                .build();
    }
}
