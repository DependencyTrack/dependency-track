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

import org.jspecify.annotations.Nullable;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

/// @since 5.1.0
public final class QueryTimeoutException extends RuntimeException {

    private final String sqlState;

    private QueryTimeoutException(@Nullable String message, Throwable cause, String sqlState) {
        super(message, cause);
        this.sqlState = sqlState;
    }

    public static @Nullable QueryTimeoutException of(Throwable throwable) {
        final PSQLException psqlException = PSQLExceptions.find(throwable);
        if (psqlException == null
                || !PSQLState.QUERY_CANCELED.getState().equals(psqlException.getSQLState())) {
            return null;
        }
        
        return new QueryTimeoutException(
                psqlException.getMessage(),
                throwable,
                psqlException.getSQLState());
    }

    public String getSqlState() {
        return sqlState;
    }

}
