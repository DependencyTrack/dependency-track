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
package org.dependencytrack.common.datasource;

import org.jspecify.annotations.Nullable;

/// @since 5.1.0
public final class QueryTimeout {

    private static final ScopedValue<Boolean> BYPASSED = ScopedValue.newInstance();

    private QueryTimeout() {
    }

    /// Runs {@code op} with the data source's global query timeout bypassed.
    ///
    /// To be used for operations that may legitimately exceed query timeouts,
    /// e.g. calls of stored procedures operating on large volumes of data.
    ///
    /// @param op  the operation to run without query timeout.
    /// @param <T> type of the return value.
    /// @param <X> type of the exception.
    /// @return the result of the operation.
    public static <T, X extends Throwable> @Nullable T bypassing(ScopedValue.CallableOp<@Nullable T, X> op) throws X {
        if (isBypassed()) {
            return op.call();
        }

        return ScopedValue.where(BYPASSED, true).call(op);
    }

    static boolean isBypassed() {
        return BYPASSED.isBound() && BYPASSED.get();
    }

}
