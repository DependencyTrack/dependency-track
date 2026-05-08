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
package org.dependencytrack.vulnanalysis.internal;

import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.support.jdbi.mapping.PurlColumnMapper;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerFactory;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;
import org.jdbi.v3.core.Jdbi;
import org.jspecify.annotations.Nullable;

import javax.sql.DataSource;
import java.util.EnumSet;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class InternalVulnAnalyzerFactory implements VulnAnalyzerFactory, RuntimeConfigurable {

    private final DataSourceRegistry dataSourceRegistry;
    private @Nullable ConfigRegistry configRegistry;
    private @Nullable Jdbi jdbi;

    InternalVulnAnalyzerFactory(DataSourceRegistry dataSourceRegistry) {
        this.dataSourceRegistry = dataSourceRegistry;
    }

    InternalVulnAnalyzerFactory() {
        this(DataSourceRegistry.getInstance());
    }

    @Override
    public String extensionName() {
        return "internal";
    }

    @Override
    public Class<? extends VulnAnalyzer> extensionClass() {
        return InternalVulnAnalyzer.class;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
        configRegistry = serviceRegistry.require(ConfigRegistry.class);

        final String dataSourceName = configRegistry
                .getDeploymentConfig()
                .getValue("datasource.name", String.class);
        final DataSource dataSource = dataSourceRegistry.get(dataSourceName);
        jdbi = Jdbi.create(dataSource)
                .registerRowMapper(new MatchingCriteria.RowMapper())
                .registerColumnMapper(new PurlColumnMapper());
    }

    @Override
    public VulnAnalyzer create() {
        requireNonNull(configRegistry);
        requireNonNull(jdbi);

        return new InternalVulnAnalyzer(jdbi);
    }

    @Override
    public boolean isEnabled() {
        requireNonNull(configRegistry);
        return configRegistry.getRuntimeConfig(InternalVulnAnalyzerConfigV1.class).isEnabled();
    }

    @Override
    public EnumSet<VulnAnalyzerRequirement> analyzerRequirements() {
        return EnumSet.of(
                VulnAnalyzerRequirement.COMPONENT_CPE,
                VulnAnalyzerRequirement.COMPONENT_PURL);
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return RuntimeConfigSpec.of(
                new InternalVulnAnalyzerConfigV1().withEnabled(true));
    }

}
