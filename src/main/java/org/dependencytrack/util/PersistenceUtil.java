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

import org.apache.commons.collections4.CollectionUtils;

import javax.jdo.JDOHelper;
import javax.jdo.ObjectState;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

import static java.util.Collections.unmodifiableMap;
import static java.util.Objects.requireNonNull;
import static javax.jdo.ObjectState.HOLLOW_PERSISTENT_NONTRANSACTIONAL;
import static javax.jdo.ObjectState.PERSISTENT_CLEAN;
import static javax.jdo.ObjectState.PERSISTENT_DIRTY;
import static javax.jdo.ObjectState.PERSISTENT_NEW;
import static javax.jdo.ObjectState.PERSISTENT_NONTRANSACTIONAL_DIRTY;

public final class PersistenceUtil {

    public record Diff(Object before, Object after) {
    }

    /**
     * A utility class to apply changed values from one object to another object of the same type.
     * <p>
     * Changed values are recorded in a diff-like structure.
     *
     * @param <T> Type of the objects to compare
     * @since 4.10.0
     */
    public static final class Differ<T> {

        private final T existingObject;
        private final T newObject;
        private final Map<String, Diff> diffs;

        public Differ(final T existingObject, final T newObject) {
            this.existingObject = requireNonNull(existingObject, "existingObject must not be null");
            this.newObject = requireNonNull(newObject, "newObject must not be null");
            this.diffs = new HashMap<>();
        }

        /**
         * Apply value of {@code newObject}'s field to value of {@code existingObject}'s field, if both values are different.
         *
         * @param fieldName Name of the field
         * @param getter    The getter to access current values with
         * @param setter    The setter on {@code existingObject}
         * @param <V>       Type of the values being compared
         * @return {@code true} when changed, otherwise {@code false}
         */
        public <V> boolean applyIfChanged(final String fieldName, final Function<T, V> getter, final Consumer<V> setter) {
            final V existingValue = getter.apply(existingObject);
            final V newValue = getter.apply(newObject);

            if (!Objects.equals(existingValue, newValue)) {
                diffs.put(fieldName, new Diff(existingValue, newValue));
                setter.accept(newValue);
                return true;
            }

            return false;
        }

        /**
         * Apply value of {@code newObject}'s field to value of {@code existingObject}'s field, if {@code newObject}'s
         * value is not {@code null}, and both values are different.
         *
         * @param fieldName Name of the field
         * @param getter    The getter to access current values with
         * @param setter    The setter on {@code existingObject}
         * @param <V>       Type of the values being compared
         * @return {@code true} when changed, otherwise {@code false}
         */
        public <V> boolean applyIfNonNullAndChanged(final String fieldName, final Function<T, V> getter, final Consumer<V> setter) {
            final V existingValue = getter.apply(existingObject);
            final V newValue = getter.apply(newObject);

            if (newValue != null && !Objects.equals(existingValue, newValue)) {
                diffs.put(fieldName, new Diff(existingValue, newValue));
                setter.accept(newValue);
                return true;
            }

            return false;
        }

        /**
         * Apply value of {@code newObject}'s field to value of {@code existingObject}'s field, if both values are
         * different, but not {@code null} or empty. In other words, {@code null} and empty are considered equal.
         *
         * @param fieldName Name of the field
         * @param getter    The getter to access current values with
         * @param setter    The setter on {@code existingObject}
         * @param <V>       Type of the items inside the {@link Collection} being compared
         * @param <C>       Type of the {@link Collection} being compared
         * @return
         */
        public <V, C extends Collection<V>> boolean applyIfNonEmptyAndChanged(final String fieldName, final Function<T, C> getter, final Consumer<C> setter) {
            final C existingValue = getter.apply(existingObject);
            final C newValue = getter.apply(newObject);

            if (CollectionUtils.isEmpty(existingValue) && CollectionUtils.isEmpty(newValue)) {
                return false;
            }

            if (!Objects.equals(existingValue, newValue)) {
                diffs.put(fieldName, new Diff(existingValue, newValue));
                setter.accept(newValue);
                return true;
            }

            return false;
        }

        public Map<String, Diff> getDiffs() {
            return unmodifiableMap(diffs);
        }

    }

    private PersistenceUtil() {
    }

    /**
     * Utility method to ensure that a given object is in a persistent state.
     * <p>
     * Useful when an object is supposed to be used as JDOQL query parameter,
     * or changes made on it are intended to be flushed to the database.
     * <p>
     * Performing these operations on a non-persistent object will have to effect.
     * It is preferable to catch these cases earlier to later.
     *
     * @param object  The object to check the state of
     * @param message Message to use for the exception, if object is not persistent
     * @throws IllegalStateException When the object is not in a persistent state
     * @see <a href="https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#lifecycle">Object Lifecycle</a>
     * @since 4.10.0
     */
    public static void assertPersistent(final Object object, final String message) {
        final ObjectState objectState = JDOHelper.getObjectState(object);
        if (objectState != PERSISTENT_CLEAN
                && objectState != PERSISTENT_DIRTY
                && objectState != PERSISTENT_NEW
                && objectState != PERSISTENT_NONTRANSACTIONAL_DIRTY
                && objectState != HOLLOW_PERSISTENT_NONTRANSACTIONAL) {
            throw new IllegalStateException(message != null ? message : "Object must be persistent");
        }
    }

}
