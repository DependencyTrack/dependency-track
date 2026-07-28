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
package org.dependencytrack.support.jdbi.exception;

import java.sql.SQLException;
import java.sql.SQLRecoverableException;
import java.sql.SQLTransientException;
import java.util.Set;

/// @since 5.1.0
public final class TransientSqlErrors {

    // Transient SQLSTATE codes.
    // See https://www.postgresql.org/docs/current/errcodes-appendix.html
    private static final Set<String> TRANSIENT_SQL_STATES = Set.of(
            "08000", // connection_exception
            "08001", // sqlclient_unable_to_establish_sqlconnection
            "08003", // connection_does_not_exist
            "08004", // sqlserver_rejected_establishment_of_sqlconnection
            "08006", // connection_failure
            "08007", // transaction_resolution_unknown
            "40001", // serialization_failure
            "40P01", // deadlock_detected
            "53300", // too_many_connections
            "53400", // configuration_limit_exceeded
            "55P03", // lock_not_available
            "57P01", // admin_shutdown
            "57P02", // crash_shutdown
            "57P03" // cannot_connect_now
    );

    private TransientSqlErrors() {
    }

    /// @param throwable The [Throwable] to inspect.
    /// @return `true` when `throwable` is, or was caused by, a transient SQL error.
    public static boolean isTransient(Throwable throwable) {
        for (Throwable cause = throwable; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLRecoverableException
                    || cause instanceof SQLTransientException) {
                return true;
            }

            if (cause instanceof final SQLException sqlException) {
                final String sqlState = sqlException.getSQLState();
                if (sqlState != null && TRANSIENT_SQL_STATES.contains(sqlState)) {
                    return true;
                }
            }
        }

        return false;
    }

}
