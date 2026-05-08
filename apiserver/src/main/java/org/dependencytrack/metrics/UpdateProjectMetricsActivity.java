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
package org.dependencytrack.metrics;

import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "update-project-metrics", defaultTaskQueue = "metrics-updates")
public final class UpdateProjectMetricsActivity implements Activity<UpdateProjectMetricsArg, Void> {

    @Override
    public @Nullable Void execute(ActivityContext ctx, @Nullable UpdateProjectMetricsArg argument) throws Exception {
        if (argument == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        final UUID projectUuid = UUID.fromString(argument.getProjectUuid());
        useJdbiTransaction(handle -> handle.attach(MetricsDao.class).updateProjectMetrics(projectUuid));

        return null;
    }

}
