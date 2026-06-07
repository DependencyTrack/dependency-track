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
package org.dependencytrack.auth;

import java.util.function.Supplier;

/// Runs an action with Portfolio Access Control turned off.
///
/// Use sparingly, only when absolutely necessary.
/// Wrap only the bare minimum in [#unrestricted(Supplier)] and perform
/// follow-up access checks outside of it.
///
/// @since 5.0.0
public final class ProjectAccess {

    private static final ScopedValue<Boolean> UNRESTRICTED = ScopedValue.newInstance();

    private ProjectAccess() {
    }

    public static <T> T unrestricted(Supplier<T> supplier) {
        if (isUnrestricted()) {
            return supplier.get();
        }

        return ScopedValue.where(UNRESTRICTED, true).call(supplier::get);
    }

    public static boolean isUnrestricted() {
        return UNRESTRICTED.isBound() && UNRESTRICTED.get();
    }

}
