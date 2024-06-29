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
package org.dependencytrack.util;

import com.mysql.cj.exceptions.MysqlErrorNumbers;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.datanucleus.enhancement.Persistable;
import org.dependencytrack.persistence.QueryManager;
import org.h2.jdbc.JdbcSQLIntegrityConstraintViolationException;
import org.postgresql.util.PSQLState;

import javax.jdo.JDOHelper;
import javax.jdo.ObjectState;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import java.sql.SQLException;
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
        if (!isPersistent(object)) {
            throw new IllegalStateException(message != null ? message : "Object must be persistent");
        }
    }

    /**
     * Utility method to ensure that a given {@link Collection} is in a persistent state.
     *
     * @param objects The {@link Collection} to check the state of
     * @param message Message to use for the exception, if object is not persistent
     * @see #assertPersistent(Object, String)
     * @since 4.12.0
     */
    public static void assertPersistentAll(final Collection<?> objects, final String message) {
        if (objects == null || objects.isEmpty()) {
            return;
        }

        objects.forEach(object -> assertPersistent(object, message));
    }

    /**
     * Utility method to ensure that a given object is <strong>not</strong> in a persistent state.
     *
     * @param object  The object to check the state of
     * @param message Message to use for the exception, if object is persistent
     * @see #assertPersistent(Object, String)
     * @since 4.11.0
     */
    public static void assertNonPersistent(final Object object, final String message) {
        if (isPersistent(object)) {
            throw new IllegalStateException(message != null ? message : "Object must not be persistent");
        }
    }

    /**
     * Utility method to ensure that a given {@link Collection} is <strong>not</strong> in a persistent state.
     *
     * @param objects The {@link Collection} to check the state of
     * @param message Message to use for the exception, if object is persistent
     * @see #assertNonPersistent(Object, String)
     * @since 4.11.0
     */
    public static void assertNonPersistentAll(final Collection<?> objects, final String message) {
        if (objects == null || objects.isEmpty()) {
            return;
        }

        objects.forEach(object -> assertNonPersistent(object, message));
    }

    private static boolean isPersistent(final Object object) {
        final ObjectState objectState = JDOHelper.getObjectState(object);
        return objectState == PERSISTENT_CLEAN
                || objectState == PERSISTENT_DIRTY
                || objectState == PERSISTENT_NEW
                || objectState == PERSISTENT_NONTRANSACTIONAL_DIRTY
                || objectState == HOLLOW_PERSISTENT_NONTRANSACTIONAL;
    }

    /**
     * Evict a given object from the JDO L2 cache.
     *
     * @param qm     The {@link QueryManager} to use
     * @param object The object to evict from the cache
     * @since 4.11.0
     */
    public static void evictFromL2Cache(final QueryManager qm, final Object object) {
        final PersistenceManagerFactory pmf = qm.getPersistenceManager().getPersistenceManagerFactory();
        pmf.getDataStoreCache().evict(getDataNucleusJdoObjectId(object));
    }

    /**
     * Evict a given {@link Collection} of objects from the JDO L2 cache.
     *
     * @param qm      The {@link QueryManager} to use
     * @param objects The objects to evict from the cache
     * @since 4.11.0
     */
    public static void evictFromL2Cache(final QueryManager qm, final Collection<?> objects) {
        final PersistenceManagerFactory pmf = qm.getPersistenceManager().getPersistenceManagerFactory();
        pmf.getDataStoreCache().evictAll(getDataNucleusJdoObjectIds(objects));
    }

    private static Collection<?> getDataNucleusJdoObjectIds(final Collection<?> objects) {
        return objects.stream().map(PersistenceUtil::getDataNucleusJdoObjectId).toList();
    }

    /**
     * {@link JDOHelper#getObjectId(Object)} and {@link PersistenceManager#getObjectId(Object)}
     * return instances of {@link javax.jdo.identity.LongIdentity}, but the DataNucleus L2 cache is maintained
     * with DataNucleus-specific {@link org.datanucleus.identity.LongId}s instead.
     * <p>
     * Calling {@link javax.jdo.datastore.DataStoreCache#evict(Object)} with {@link javax.jdo.identity.LongIdentity}
     * is pretty much a no-op. The mismatch is undetectable because {@code evict} doesn't throw when a wrong identity
     * type is passed either.
     * <p>
     * (╯°□°)╯︵ ┻━┻
     *
     * @param object The object to get the JDO object ID for
     * @return A JDO object ID
     */
    private static Object getDataNucleusJdoObjectId(final Object object) {
        if (!(object instanceof final Persistable persistable)) {
            throw new IllegalArgumentException("Can't get JDO object ID from non-Persistable objects");
        }

        final Object objectId = persistable.dnGetObjectId();
        if (objectId == null) {
            throw new IllegalStateException("Object does not have a JDO object ID");
        }

        return objectId;
    }

    public static boolean isUniqueConstraintViolation(final Throwable throwable) {
        // NB: DataNucleus doesn't map constraint violation exceptions,
        //   so we have to depend on underlying JDBC driver's exception to
        //   tell us what happened. Leaky abstraction FTW.
        final Throwable rootCause = ExceptionUtils.getRootCause(throwable);

        // H2 has a dedicated exception for this.
        if (rootCause instanceof JdbcSQLIntegrityConstraintViolationException) {
            return true;
        }

        // Other RDBMSes use the SQL state to communicate errors.
        if (rootCause instanceof final SQLException se) {
            return MysqlErrorNumbers.SQL_STATE_INTEGRITY_CONSTRAINT_VIOLATION.equals(se.getSQLState()) // MySQL
                    || PSQLState.UNIQUE_VIOLATION.getState().equals(se.getSQLState()) // PostgreSQL
                    || "23000".equals(se.getSQLState()); // SQL Server
        }

        return false;
    }

}
