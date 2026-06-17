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
package org.dependencytrack.vulnanalysis;

import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Classification;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.Property;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisArg;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisRes;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerFactory;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;
import org.jdbi.v3.core.statement.Query;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ANALYZER_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "prepare-vuln-analysis")
public final class PrepareVulnAnalysisActivity implements Activity<PrepareVulnAnalysisArg, PrepareVulnAnalysisRes> {

    private static final Logger LOGGER = LoggerFactory.getLogger(PrepareVulnAnalysisActivity.class);

    private final FileStorage fileStorage;
    private final PluginManager pluginManager;

    public PrepareVulnAnalysisActivity(FileStorage fileStorage, PluginManager pluginManager) {
        this.fileStorage = fileStorage;
        this.pluginManager = pluginManager;
    }

    @Override
    public PrepareVulnAnalysisRes execute(
            ActivityContext ctx,
            @Nullable PrepareVulnAnalysisArg argument) throws Exception {
        if (argument == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, argument.getProjectUuid())) {
            LOGGER.debug("Determining applicable analyzers");
            final Map<String, Set<VulnAnalyzerRequirement>> requirementsByAnalyzer = getApplicableAnalyzers();
            if (requirementsByAnalyzer.isEmpty()) {
                LOGGER.debug("No applicable analyzers");
                return PrepareVulnAnalysisRes.getDefaultInstance();
            }
            LOGGER.debug("Applicable analyzers: {}", requirementsByAnalyzer);

            LOGGER.debug("Assembling BOM for analysis");
            final Bom bom = assembleBom(
                    argument.getProjectUuid(),
                    requirementsByAnalyzer.values().stream()
                            .flatMap(Collection::stream)
                            .collect(Collectors.toSet()));
            if (bom.getComponentsCount() == 0) {
                LOGGER.debug("Project has no analyzable components");
                return PrepareVulnAnalysisRes.getDefaultInstance();
            }
            LOGGER.debug("Assembled BOM of {} components", bom.getComponentsCount());

            final FileMetadata bomFileMetadata = storeBom(ctx, bom);
            LOGGER.debug("Stored BOM file at {}", bomFileMetadata.getLocation());

            return PrepareVulnAnalysisRes.newBuilder()
                    .addAllAnalyzers(requirementsByAnalyzer.keySet())
                    .setBomFileMetadata(bomFileMetadata)
                    .build();
        }
    }

    private Map<String, Set<VulnAnalyzerRequirement>> getApplicableAnalyzers() {
        final var requirementsByAnalyzer = new HashMap<String, Set<VulnAnalyzerRequirement>>();
        for (final var factory : pluginManager.getFactories(VulnAnalyzer.class)) {
            final var vulnAnalyzerFactory = (VulnAnalyzerFactory) factory;
            final var analyzerName = vulnAnalyzerFactory.extensionName();

            try (var _ = MDC.putCloseable(MDC_VULN_ANALYZER_NAME, analyzerName)) {
                if (vulnAnalyzerFactory.isEnabled()) {
                    LOGGER.debug("Analyzer is enabled");
                    requirementsByAnalyzer
                            .computeIfAbsent(analyzerName, k -> new HashSet<>())
                            .addAll(vulnAnalyzerFactory.analyzerRequirements());
                } else {
                    LOGGER.debug("Analyzer is disabled");
                }
            }
        }

        return requirementsByAnalyzer;
    }

    private Bom assembleBom(String projectUuid, Set<VulnAnalyzerRequirement> requirements) {
        final boolean requiresProperties = requirements.contains(VulnAnalyzerRequirement.COMPONENT_PROPERTIES);

        final Map<Long, List<Property>> propertiesByComponentId;
        if (requiresProperties) {
            propertiesByComponentId = withJdbiHandle(handle -> handle
                    .createQuery("""
                            SELECT cp."COMPONENT_ID"
                                 , cp."GROUPNAME"
                                 , cp."PROPERTYNAME"
                                 , cp."PROPERTYVALUE"
                              FROM "COMPONENT_PROPERTY" AS cp
                              JOIN "COMPONENT" AS c
                                ON c."ID" = cp."COMPONENT_ID"
                             WHERE c."PROJECT_ID" = (SELECT "ID" FROM "PROJECT" WHERE "UUID" = CAST(:projectUuid AS UUID))
                            """)
                    .bind("projectUuid", projectUuid)
                    .reduceRows(
                            new HashMap<>(),
                            (map, rowView) -> {
                                final long componentId = rowView.getColumn("component_id", Long.class);
                                final String groupName = rowView.getColumn("groupname", String.class);
                                final String propertyName = rowView.getColumn("propertyname", String.class);
                                final String propertyValue = rowView.getColumn("propertyvalue", String.class);

                                map.computeIfAbsent(componentId, k -> new ArrayList<>())
                                        .add(Property.newBuilder()
                                                .setName(groupName != null
                                                        ? "%s:%s".formatted(groupName, propertyName)
                                                        : propertyName)
                                                .setValue(propertyValue)
                                                .build());
                                return map;
                            }));
        } else {
            propertiesByComponentId = Map.of();
        }

        final List<Component> components = withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "ID"
                         , "GROUP"
                         , "NAME"
                         , "VERSION"
                         , "INTERNAL"
                    <#if requirements?seq_contains('COMPONENT_CPE')>
                         , "CPE"
                    </#if>
                    <#if requirements?seq_contains('COMPONENT_PURL')>
                         , "PURL"
                    </#if>
                    <#if requirements?seq_contains('COMPONENT_TYPE')>
                         , "CLASSIFIER"
                    </#if>
                      FROM "COMPONENT"
                     WHERE "PROJECT_ID" = (SELECT "ID" FROM "PROJECT" WHERE "UUID" = CAST(:projectUuid AS UUID))
                    """);

            return query
                    .bind("projectUuid", projectUuid)
                    .define("requirements", requirements)
                    .map((rs, stmtCtx) -> {
                        final long componentId = rs.getLong("id");

                        final var componentBuilder = Component.newBuilder()
                                .setBomRef(String.valueOf(componentId))
                                .setName(rs.getString("name"));
                        Optional.ofNullable(rs.getString("group"))
                                .ifPresent(componentBuilder::setGroup);
                        Optional.ofNullable(rs.getString("version"))
                                .ifPresent(componentBuilder::setVersion);
                        if (rs.getBoolean("internal")) {
                            componentBuilder.addProperties(
                                    Property.newBuilder()
                                            .setName("dependencytrack:internal:is-internal-component")
                                            .setValue("true")
                                            .build());
                        }
                        if (requirements.contains(VulnAnalyzerRequirement.COMPONENT_CPE)) {
                            Optional.ofNullable(rs.getString("cpe"))
                                    .ifPresent(componentBuilder::setCpe);
                        }
                        if (requirements.contains(VulnAnalyzerRequirement.COMPONENT_PURL)) {
                            Optional.ofNullable(rs.getString("purl"))
                                    .ifPresent(componentBuilder::setPurl);
                        }
                        if (requirements.contains(VulnAnalyzerRequirement.COMPONENT_TYPE)) {
                            Optional.ofNullable(rs.getString("classifier"))
                                    .map(Classifier::valueOf)
                                    .map(PrepareVulnAnalysisActivity::convertClassifier)
                                    .ifPresent(componentBuilder::setType);
                        }
                        if (requiresProperties) {
                            final List<Property> properties = propertiesByComponentId.get(componentId);
                            if (properties != null && !properties.isEmpty()) {
                                componentBuilder.addAllProperties(properties);
                            }
                        }

                        return componentBuilder.build();
                    })
                    .list();
        });

        return Bom.newBuilder()
                .addAllComponents(components)
                .build();
    }

    private FileMetadata storeBom(ActivityContext ctx, Bom bom) throws IOException {
        try {
            return fileStorage.store(
                    "vuln-analysis/%s/bom.proto".formatted(ctx.workflowRunId()),
                    "application/protobuf",
                    new ByteArrayInputStream(bom.toByteArray()));
        } catch (NoSuchExtensionException e) {
            throw new TerminalApplicationFailureException(e);
        }
    }

    private static Classification convertClassifier(final Classifier classifier) {
        return switch (classifier) {
            case APPLICATION -> Classification.CLASSIFICATION_APPLICATION;
            case FRAMEWORK -> Classification.CLASSIFICATION_FRAMEWORK;
            case LIBRARY -> Classification.CLASSIFICATION_LIBRARY;
            case OPERATING_SYSTEM -> Classification.CLASSIFICATION_OPERATING_SYSTEM;
            case DEVICE -> Classification.CLASSIFICATION_DEVICE;
            case FILE -> Classification.CLASSIFICATION_FILE;
            case CONTAINER -> Classification.CLASSIFICATION_CONTAINER;
            case FIRMWARE -> Classification.CLASSIFICATION_FIRMWARE;
            case DEVICE_DRIVER -> Classification.CLASSIFICATION_DEVICE_DRIVER;
            case PLATFORM -> Classification.CLASSIFICATION_PLATFORM;
            case MACHINE_LEARNING_MODEL -> Classification.CLASSIFICATION_MACHINE_LEARNING_MODEL;
            case DATA -> Classification.CLASSIFICATION_DATA;
            case CRYPTOGRAPHIC_ASSET -> Classification.CLASSIFICATION_CRYPTOGRAPHIC_ASSET;
        };
    }

}
