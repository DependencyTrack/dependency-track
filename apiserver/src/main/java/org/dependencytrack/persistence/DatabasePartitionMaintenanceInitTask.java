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
package org.dependencytrack.persistence;

import org.dependencytrack.init.InitTask;
import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.MetricsDao;

/**
 * @since 5.0.0
 */
public final class DatabasePartitionMaintenanceInitTask implements InitTask {

    @Override
    public int priority() {
        return PRIORITY_HIGHEST - 10;
    }

    @Override
    public String name() {
        return "database-partition-maintenance";
    }

    @Override
    public void execute(final InitTaskContext ctx) throws Exception {
        final var jdbi = JdbiFactory.createLocalJdbi(ctx.dataSource());
        jdbi.useTransaction(handle -> handle.attach(MetricsDao.class).createMetricsPartitions());
    }

}
