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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

public final class PersistenceUtil {

    public static <T, V> boolean applyIfChanged(final T existingObject, final T newObject,
                                                final Function<T, V> getter, final Consumer<V> setter) {
        final V existingValue = getter.apply(existingObject);
        final V newValue = getter.apply(newObject);

        if (!Objects.equals(existingValue, newValue)) {
            setter.accept(newValue);
            return true;
        }

        return false;
    }

    public static <T, V> boolean applyIfNonNullAndChanged(final T existingObject, final T newObject,
                                                          final Function<T, V> getter, final Consumer<V> setter) {
        final V existingValue = getter.apply(existingObject);
        final V newValue = getter.apply(newObject);

        if (newValue != null && !Objects.equals(existingValue, newValue)) {
            setter.accept(newValue);
            return true;
        }

        return false;
    }

}
