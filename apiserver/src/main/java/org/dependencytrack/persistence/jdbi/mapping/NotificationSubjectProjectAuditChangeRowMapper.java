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
package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.notification.proto.v1.Component;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.Vulnerability;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysis;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class NotificationSubjectProjectAuditChangeRowMapper implements RowMapper<VulnerabilityAnalysisDecisionChangeSubject> {

    @Override
    public VulnerabilityAnalysisDecisionChangeSubject map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final RowMapper<Component> componentRowMapper = ctx.findRowMapperFor(Component.class).orElseThrow();
        final RowMapper<Project> projectRowMapper = ctx.findRowMapperFor(Project.class).orElseThrow();
        final RowMapper<Vulnerability> vulnRowMapper = ctx.findRowMapperFor(Vulnerability.class).orElseThrow();
        final VulnerabilityAnalysis.Builder vulnAnalysisBuilder = VulnerabilityAnalysis.newBuilder()
                .setComponent(componentRowMapper.map(rs, ctx))
                .setProject(projectRowMapper.map(rs, ctx))
                .setVulnerability(vulnRowMapper.map(rs, ctx));
        maybeSet(rs, "vulnAnalysisState", ResultSet::getString, vulnAnalysisBuilder::setState);
        maybeSet(rs, "isVulnAnalysisSuppressed", ResultSet::getBoolean, vulnAnalysisBuilder::setSuppressed);
        final VulnerabilityAnalysisDecisionChangeSubject.Builder builder = VulnerabilityAnalysisDecisionChangeSubject.newBuilder()
                .setComponent(componentRowMapper.map(rs, ctx))
                .setProject(projectRowMapper.map(rs, ctx))
                .setVulnerability(vulnRowMapper.map(rs, ctx))
                .setAnalysis(vulnAnalysisBuilder);
        return builder.build();
    }

}
