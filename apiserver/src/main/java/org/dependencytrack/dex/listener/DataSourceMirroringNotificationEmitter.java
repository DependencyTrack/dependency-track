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
package org.dependencytrack.dex.listener;

import org.dependencytrack.dex.api.WorkflowSpecs;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEvent;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEventListener;
import org.dependencytrack.kevdatasource.MirrorKevDataSourceWorkflow;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.vulndatasource.MirrorVulnDataSourceWorkflow;
import org.dependencytrack.vulndatasource.api.VulnDataSource;

import java.util.ArrayList;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.api.NotificationFactory.createDataSourceMirroringCompletedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createDataSourceMirroringFailedNotification;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/// @since 5.2.0
public final class DataSourceMirroringNotificationEmitter implements WorkflowRunsCompletedEventListener {

    private record DataSourceType(String label, Class<? extends ExtensionPoint> extensionPointClass) {}

    private static final Map<String, DataSourceType> DATA_SOURCE_TYPE_BY_WORKFLOW_NAME = Map.of(
            WorkflowSpecs.of(MirrorKevDataSourceWorkflow.class).name(),
            new DataSourceType("KEV", KevDataSource.class),
            WorkflowSpecs.of(MirrorVulnDataSourceWorkflow.class).name(),
            new DataSourceType("vulnerability", VulnDataSource.class));

    private final PluginManager pluginManager;

    public DataSourceMirroringNotificationEmitter(PluginManager pluginManager) {
        this.pluginManager = requireNonNull(pluginManager, "pluginManager must not be null");
    }

    @Override
    public void onEvent(WorkflowRunsCompletedEvent event) {
        final var notifications = new ArrayList<Notification>();

        for (final WorkflowRunMetadata run : event.completedRuns()) {
            final DataSourceType dataSourceType = DATA_SOURCE_TYPE_BY_WORKFLOW_NAME.get(run.workflowName());
            final String instanceId = run.workflowInstanceId();
            if (dataSourceType == null || instanceId == null) {
                continue;
            }

            // Instance IDs have the format "<workflowName>:<dataSourceName>".
            final String dataSourceName =
                    instanceId.substring(run.workflowName().length() + 1);
            final String displayName = getDisplayName(dataSourceType, dataSourceName);

            switch (run.status()) {
                case COMPLETED ->
                    notifications.add(
                            createDataSourceMirroringCompletedNotification(dataSourceType.label(), displayName));
                case FAILED ->
                    notifications.add(createDataSourceMirroringFailedNotification(dataSourceType.label(), displayName));
                default -> {}
            }
        }

        if (!notifications.isEmpty()) {
            useJdbiTransaction(handle -> new JdbiNotificationEmitter(handle).emitAll(notifications));
        }
    }

    private String getDisplayName(DataSourceType dataSourceType, String dataSourceName) {
        try {
            final ExtensionFactory<?> factory =
                    pluginManager.getFactory(dataSourceType.extensionPointClass(), dataSourceName);
            return factory.displayName();
        } catch (NoSuchExtensionException e) {
            return dataSourceName;
        }
    }
}
