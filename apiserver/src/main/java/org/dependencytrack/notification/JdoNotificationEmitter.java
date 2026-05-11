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

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import org.dependencytrack.notification.api.emission.NotificationEmitter;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;
import java.util.Collection;

import static java.util.Objects.requireNonNull;

/**
 * A {@link NotificationEmitter} using the JDO API for database interactions.
 *
 * @since 5.0.0
 */
public final class JdoNotificationEmitter extends JdbcNotificationEmitter {

    private final PersistenceManager pm;

    JdoNotificationEmitter(PersistenceManager pm, MeterRegistry meterRegistry) {
        super(null, meterRegistry);
        this.pm = requireNonNull(pm, "pm must not be null");
    }

    JdoNotificationEmitter(QueryManager qm, MeterRegistry meterRegistry) {
        this(requireNonNull(qm, "qm must not be null").getPersistenceManager(), meterRegistry);
    }

    public JdoNotificationEmitter(QueryManager qm) {
        this(qm, Metrics.globalRegistry);
    }

    @Override
    public void emitAll(Collection<Notification> notifications) {
        // JDO requires the JDOConnection to be closed when direct access to
        // the underlying native JDBC connection is no longer required.
        final JDOConnection jdoConnection = pm.getDataStoreConnection();
        final var nativeConnection = (Connection) jdoConnection.getNativeConnection();

        try {
            super.emitAll(nativeConnection, notifications);
        } finally {
            jdoConnection.close();
        }
    }

}
