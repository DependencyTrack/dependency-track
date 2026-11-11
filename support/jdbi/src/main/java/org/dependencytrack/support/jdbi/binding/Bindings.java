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
package org.dependencytrack.support.jdbi.binding;

import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.function.Function;

/// @since 5.3.0
public final class Bindings {

    private Bindings() {}

    /// Extracts one column from rows, for binding as an array parameter, e.g. to `UNNEST`.
    public static <T, V> List<@Nullable V> columnValues(List<T> rows, Function<T, @Nullable V> getter) {
        return rows.stream().map(getter).toList();
    }
}
