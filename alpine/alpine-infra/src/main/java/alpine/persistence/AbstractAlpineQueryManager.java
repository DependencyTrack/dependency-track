/*
 * This file is part of Alpine.
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
package alpine.persistence;

import alpine.common.validation.RegexSequence;
import alpine.resources.AlpineRequest;
import org.datanucleus.api.jdo.JDOQuery;

import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.metadata.MemberMetadata;
import javax.jdo.metadata.TypeMetadata;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Base persistence manager that implements AutoCloseable so that the PersistenceManager will
 * be automatically closed when used in a try-with-resource block.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public abstract class AbstractAlpineQueryManager implements AutoCloseable {

    private static final Lock IPMF_LOCK = new ReentrantLock();
    private static IPersistenceManagerFactory IPMF;

    protected final Principal principal;
    protected final Pagination pagination;
    protected final String filter;
    protected final String orderBy;
    protected final OrderDirection orderDirection;
    protected final PersistenceManager pm;

    public static IPersistenceManagerFactory getPersistenceManagerFactory() {
        if (IPMF != null) {
            return IPMF;
        }

        IPMF_LOCK.lock();
        try {
            if (IPMF == null) {
                IPMF = ServiceLoader
                        .load(IPersistenceManagerFactory.class)
                        .findFirst()
                        .orElseThrow();
            }
            return IPMF;
        } finally {
            IPMF_LOCK.unlock();
        }
    }

    /**
     * Specifies a non-default PersistenceManager to use.
     * @param pm the JDO PersistenceManager to use
     * @since 1.4.3
     */
    public AbstractAlpineQueryManager(final PersistenceManager pm) {
        this.pm = pm;
        principal = null;
        pagination = new Pagination(Pagination.Strategy.NONE, 0, 0);
        filter = null;
        orderBy = null;
        orderDirection = OrderDirection.UNSPECIFIED;
    }

    /**
     * Default constructor
     */
    public AbstractAlpineQueryManager() {
        pm = getPersistenceManagerFactory().getPersistenceManager();
        principal = null;
        pagination = new Pagination(Pagination.Strategy.NONE, 0, 0);
        filter = null;
        orderBy = null;
        orderDirection = OrderDirection.UNSPECIFIED;
    }

    /**
     * Constructs a new QueryManager. Deconstructs the specified AlpineRequest
     * into its individual components including pagination and ordering.
     * @param request an AlpineRequest object
     * @since 1.0.0
     */
    public AbstractAlpineQueryManager(final AlpineRequest request) {
        pm = getPersistenceManagerFactory().getPersistenceManager();
        this.principal = request.getPrincipal();
        this.pagination = request.getPagination();
        this.filter = request.getFilter();
        this.orderBy = request.getOrderBy();
        this.orderDirection = request.getOrderDirection();
    }

    /**
     * Constructs a new QueryManager. Deconstructs the specified AlpineRequest
     * into its individual components including pagination and ordering.
     * @param pm the JDO PersistenceManager to use
     * @param request an AlpineRequest object
     * @since 1.9.3
     */
    public AbstractAlpineQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        this.pm = pm;
        this.principal = request.getPrincipal();
        this.pagination = request.getPagination();
        this.filter = request.getFilter();
        this.orderBy = request.getOrderBy();
        this.orderDirection = request.getOrderDirection();
    }

    /**
     * Wrapper around {@link Query#executeWithArray(Object...)} that adds transparent support for
     * pagination and ordering of results via {@link #decorate(Query)}.
     * @param query the JDO Query object to execute
     * @param parameters the <code>Object</code> array with all the parameters
     * @return a PaginatedResult object
     * @since 1.0.0
     */
    public PaginatedResult execute(final Query<?> query, final Object... parameters) {
        final long count = getCount(query, parameters);
        decorate(query);
        return new PaginatedResult()
                .objects(executeAndCloseWithArray(query, parameters))
                .total(count);
    }

    /**
     * Wrapper around {@link Query#executeWithMap(Map)} that adds transparent support for
     * pagination and ordering of results via {@link #decorate(Query)}.
     * @param query the JDO Query object to execute
     * @param parameters the <code>Map</code> containing all the parameters.
     * @return a PaginatedResult object
     * @since 1.0.0
     */
    public PaginatedResult execute(final Query<?> query, final Map<String, Object> parameters) {
        final long count = getCount(query, parameters);
        decorate(query);
        return new PaginatedResult()
                .objects(executeAndCloseWithMap(query, parameters))
                .total(count);
    }

    /**
     * Given a query, this method will decorate that query with pagination, ordering,
     * and sorting direction. Specific checks are performed to ensure the execution
     * of the query is capable of being paged and that ordering can be securely performed.
     * @param query the JDO Query object to execute
     * @return a Collection of objects
     * @since 1.0.0
     */
    public <T> Query<T> decorate(final Query<T> query) {
        // Clear the result to fetch if previously specified (i.e. by getting count)
        query.setResult(null);
        if (pagination != null && pagination.isPaginated()) {
            final long begin = pagination.getOffset();
            final long end = begin + pagination.getLimit();
            query.setRange(begin, end);
        }
        if (orderBy != null && RegexSequence.Pattern.STRING_IDENTIFIER.matcher(orderBy).matches() && orderDirection != OrderDirection.UNSPECIFIED) {
            // Check to see if the specified orderBy field is defined in the class being queried.
            boolean found = false;
            // NB: Only persistent fields can be used as sorting subject.
            final org.datanucleus.store.query.Query<T> iq = ((JDOQuery<T>) query).getInternalQuery();
            final String candidateField = orderBy.contains(".") ? orderBy.substring(0, orderBy.indexOf('.')) : orderBy;
            final TypeMetadata candidateTypeMetadata = pm.getPersistenceManagerFactory().getMetadata(iq.getCandidateClassName());
            if (candidateTypeMetadata == null) {
                // NB: If this happens then the entire query is broken and needs programmatic fixing.
                // Throwing an exception here to make this painfully obvious.
                throw new IllegalStateException("""
                        Persistence type metadata for candidate class %s could not be found. \
                        Querying for non-persistent types is not supported, correct your query.\
                        """.formatted(iq.getCandidateClassName()));
            }
            boolean foundPersistentMember = false;
            for (final MemberMetadata memberMetadata : candidateTypeMetadata.getMembers()) {
                if (candidateField.equals(memberMetadata.getName())) {
                    foundPersistentMember = true;
                    break;
                }
            }
            if (foundPersistentMember) {
                query.setOrdering(orderBy + " " + orderDirection.name().toLowerCase());
            } else {
                throw new IllegalArgumentException(
                        "Sorting by field '%s' is not supported".formatted(candidateField));
            }
        }
        return query;
    }

    /**
     * Returns the number of items that would have resulted from returning all object.
     * This method is performant in that the objects are not actually retrieved, only
     * the count.
     * @param query the query to return a count from
     * @param parameters the <code>Object</code> array with all the parameters
     * @return the number of items
     * @since 1.0.0
     */
    public long getCount(final Query<?> query, final Object... parameters) {
        final org.datanucleus.store.query.Query<?> internalQuery = ((JDOQuery<?>) query).getInternalQuery();
        final String originalOrdering = internalQuery.getOrdering();
        query.setOrdering(null);
        query.setResult("count(this)");
        try {
            // NB: Don't close the query as it is to be reused.
            return (Long) query.executeWithArray(parameters);
        } finally {
            query.setOrdering(originalOrdering);
            query.setResult(null);
        }
    }

    /**
     * Returns the number of items that would have resulted from returning all object.
     * This method is performant in that the objects are not actually retrieved, only
     * the count.
     * @param query the query to return a count from
     * @param parameters the <code>Map</code> containing all the parameters.
     * @return the number of items
     * @since 1.0.0
     */
    public long getCount(final Query<?> query, final Map<String, Object> parameters) {
        final org.datanucleus.store.query.Query<?> internalQuery = ((JDOQuery<?>) query).getInternalQuery();
        final String originalOrdering = internalQuery.getOrdering();
        query.setOrdering(null);
        query.setResult("count(this)");
        try {
            // NB: Don't close the query as it is to be reused.
            return (Long) query.executeWithMap(parameters);
        } finally {
            query.setOrdering(originalOrdering);
            query.setResult(null);
        }
    }

    /**
     * Returns the number of items that would have resulted from returning all object.
     * This method is performant in that the objects are not actually retrieved, only
     * the count.
     * @param cls the persistence-capable class to query
     * @return the number of items
     * @param <T> candidate type for the query
     * @since 1.0.0
     */
    public <T> long getCount(final Class<T> cls) {
        final Query<T> query = pm.newQuery(cls);
        query.setResult("count(id)");
        return executeAndCloseResultUnique(query, Long.class);
    }

    /**
     * Persists the specified PersistenceCapable object.
     * @param object a PersistenceCapable object
     * @param <T> the type to return
     * @return the persisted object
     */
    public <T> T persist(T object) {
        return callInTransaction(() -> pm.makePersistent(object));
    }

    /**
     * Persists the specified PersistenceCapable objects.
     * @param pcs an array of PersistenceCapable objects
     * @param <T> the type to return
     * @return the persisted objects
     */
    public <T> T[] persist(T... pcs) {
        return callInTransaction(() -> pm.makePersistentAll(pcs));
    }

    /**
     * Persists the specified PersistenceCapable objects.
     * @param pcs a collection of PersistenceCapable objects
     * @param <T> the type to return
     * @return the persisted objects
     */
    public <T> Collection<T> persist(Collection<T> pcs) {
        return callInTransaction(() -> pm.makePersistentAll(pcs));
    }

    /**
     * Deletes one or more PersistenceCapable objects.
     * @param objects an array of one or more objects to delete
     * @since 1.0.0
     */
    public void delete(Object... objects) {
        runInTransaction(() -> pm.deletePersistentAll(objects));
    }

    /**
     * Deletes one or more PersistenceCapable objects.
     * @param collection a collection of one or more objects to delete
     * @since 1.0.0
     */
    public void delete(Collection<?> collection) {
        runInTransaction(() -> pm.deletePersistentAll(collection));
    }

    /**
     * Refreshes and detaches an object by its ID.
     * @param <T> A type parameter. This type will be returned
     * @param clazz the persistence class to retrieve the ID for
     * @param id the object id to retrieve
     * @return an object of the specified type
     * @since 1.3.0
     */
    public <T> T detach(Class<T> clazz, Object id) {
        try (var _ = new ScopedCustomization(pm).withDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS)) {
            return pm.detachCopy(pm.getObjectById(clazz, id));
        }
    }

    public <T> T detach(final T object) {
        try (var _ = new ScopedCustomization(pm).withDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS)) {
            return pm.detachCopy(object);
        }
    }

    /**
     * Transition {@code object} into the transient state, detaching it from the persistence context.
     * This does <strong>not</strong> create a copy of {@code object}!
     *
     * @param object The object to make transient
     * @param <T>    The type of {@code object}
     * @return The transitioned object
     * @see <a href="https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#lifecycle">JDO Object Lifecycle</a>
     */
    public <T> T makeTransient(final T object) {
        pm.makeTransient(object);
        return object;
    }

    /**
     * Transitions {@code collection} into the transient state, detaching its items from the persistence context.
     * This does <strong>not</strong> create a copy of {@code collection}, or the items within it!
     *
     * @param collection The collection to make transient
     * @param <C>        The type of {@code collection}
     * @param <T>        The type of the items within {@code collection}
     * @return The transitioned collection
     * @see <a href="https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#lifecycle">JDO Object Lifecycle</a>
     */
    public <T, C extends Collection<T>> C makeTransientAll(final C collection) {
        pm.makeTransientAll(collection);
        return collection;
    }

    /**
     * Retrieves an object by its ID.
     * @param <T> A type parameter. This type will be returned
     * @param clazz the persistence class to retrieve the ID for
     * @param id the object id to retrieve
     * @return an object of the specified type
     * @since 1.0.0
     */
    public <T> T getObjectById(Class<T> clazz, Object id) {
        return pm.getObjectById(clazz, id);
    }

    /**
     * Retrieves an object by its UUID.
     * @param <T> A type parameter. This type will be returned
     * @param clazz the persistence class to retrieve the ID for
     * @param uuid the uuid of the object to retrieve
     * @return an object of the specified type
     * @since 1.0.0
     */
    public <T> T getObjectByUuid(Class<T> clazz, UUID uuid) {
        final Query<T> query = pm.newQuery(clazz, "uuid == :uuid");
        query.setParameters(uuid);
        return executeAndCloseUnique(query);
    }

    /**
     * Retrieves an object by its UUID.
     * @param <T> A type parameter. This type will be returned
     * @param clazz the persistence class to retrieve the ID for
     * @param uuid the uuid of the object to retrieve
     * @return an object of the specified type
     * @since 1.0.0
     */
    public <T> T getObjectByUuid(Class<T> clazz, String uuid) {
        return getObjectByUuid(clazz, UUID.fromString(uuid));
    }

    /**
     * Retrieves an object by its UUID.
     * @param <T> A type parameter. This type will be returned
     * @param clazz the persistence class to retrieve the ID for
     * @param uuid the uuid of the object to retrieve
     * @param fetchGroup the JDO fetch group to use when making the query
     * @return an object of the specified type
     * @since 1.0.0
     */
    public <T> T getObjectByUuid(Class<T> clazz, UUID uuid, String fetchGroup) {
        final Query<T> query = pm.newQuery(clazz, "uuid == :uuid");
        query.getFetchPlan().addGroup(fetchGroup);
        query.setParameters(uuid);
        return executeAndCloseUnique(query);
    }

    /**
     * Retrieves an object by its UUID.
     * @param <T> A type parameter. This type will be returned
     * @param clazz the persistence class to retrieve the ID for
     * @param uuid the uuid of the object to retrieve
     * @param fetchGroup the JDO fetch group to use when making the query
     * @return an object of the specified type
     * @since 1.0.0
     */
    public <T> T getObjectByUuid(Class<T> clazz, String uuid, String fetchGroup) {
        return getObjectByUuid(clazz, UUID.fromString(uuid), fetchGroup);
    }

    /**
     * Used to return the first record in a collection. This method is intended to be used
     * to wrap {@link Query#execute()} and its derivatives.
     * @param object a collection object (or anything that extends collection)
     * @param <T> the type of object returned, or null if object was null, not a collection, or collection was empty
     * @return A single results
     * @since 1.4.4
     */
    @SuppressWarnings("unchecked")
    public <T> T singleResult(Object object) {
        if (object == null) {
            return null;
        }
        if (object instanceof Collection) {
            final Collection<T> result = (Collection<T>)object;
            return result.isEmpty() ? null : result.iterator().next();
        }
        return null;
    }

    /**
     * Closes the PersistenceManager instance.
     * @since 1.0.0
     */
    public void close() {
        if (pm != null) {
            pm.close();
        }
    }

    public PersistenceManager getPersistenceManager() {
        return pm;
    }

    /**
     * Execute a {@link Callable} within the context of a transaction.
     *
     * @param options  The {@link Transaction.Options} to apply to the transaction
     * @param callable The {@link Callable} to execute
     * @param <T>      Type of the result returned by {@code callable}
     * @return The result of {@code callable} after transaction commit
     */
    public <T> T callInTransaction(final Transaction.Options options, final Callable<T> callable) {
        return Transaction.call(pm, options, callable);
    }

    /**
     * Execute a {@link Callable} within the context of a transaction.
     *
     * @param callable The {@link Callable} to execute
     * @param <T>      Type of the result returned by {@code callable}
     * @return The result of {@code callable} after transaction commit
     */
    public <T> T callInTransaction(final Callable<T> callable) {
        return callInTransaction(Transaction.defaultOptions(), callable);
    }

    /**
     * Execute a {@link Runnable} within the context of a transaction.
     *
     * @param options  The {@link Transaction.Options} to apply to the transaction
     * @param runnable The {@link Callable} to execute
     */
    public void runInTransaction(final Transaction.Options options, final Runnable runnable) {
        callInTransaction(options, () -> {
            runnable.run();
            return null;
        });
    }

    /**
     * Execute a {@link Runnable} within the context of a transaction.
     *
     * @param runnable The {@link Callable} to execute
     */
    public void runInTransaction(final Runnable runnable) {
        runInTransaction(Transaction.defaultOptions(), runnable);
    }

    /**
     * Wrapper around {@link Query#execute()} that closes the {@link Query}
     * after its result has been retrieved, to prevent resource leakage.
     *
     * @param query The {@link Query} to execute
     * @return The {@link Query}'s result
     */
    protected Object executeAndClose(final Query<?> query) {
        try {
            final Object result = query.execute();
            if (result instanceof final Collection<?> resultCollection) {
                return new ArrayList<>(resultCollection);
            }

            return result;
        } finally {
            query.closeAll();
        }
    }

    /**
     * Wrapper around {@link Query#executeWithArray(Object...)} that closes the {@link Query}
     * after its result has been retrieved, to prevent resource leakage.
     *
     * @param query      The {@link Query} to execute
     * @param parameters The query parameters
     * @return The {@link Query}'s result
     */
    protected Object executeAndCloseWithArray(final Query<?> query, final Object... parameters) {
        try {
            final Object result = query.executeWithArray(parameters);
            if (result instanceof final Collection<?> resultCollection) {
                return new ArrayList<>(resultCollection);
            }

            return result;
        } finally {
            query.closeAll();
        }
    }

    /**
     * Wrapper around {@link Query#executeWithMap(Map)} that closes the {@link Query}
     * after its result has been retrieved, to prevent resource leakage.
     *
     * @param query      The {@link Query} to execute
     * @param parameters The query parameters
     * @return The {@link Query}'s result
     */
    protected Object executeAndCloseWithMap(final Query<?> query, final Map<String, Object> parameters) {
        try {
            final Object result = query.executeWithMap(parameters);
            if (result instanceof final Collection<?> resultCollection) {
                return new ArrayList<>(resultCollection);
            }

            return result;
        } finally {
            query.closeAll();
        }
    }

    /**
     * Wrapper around {@link Query#executeUnique()} that closes the {@link Query}
     * after its result has been retrieved, to prevent resource leakage.
     *
     * @param query The {@link Query} to execute
     * @param <T>   Type of the {@link Query}'s result
     * @return The {@link Query}'s result
     */
    protected <T> T executeAndCloseUnique(final Query<T> query) {
        try {
            return query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

    /**
     * Wrapper around {@link Query#executeList()} that closes the {@link Query}
     * after its result has been retrieved, to prevent resource leakage.
     *
     * @param query The {@link Query} to execute
     * @param <T>   Type of the {@link Query}'s result
     * @return The {@link Query}'s result
     */
    protected <T> List<T> executeAndCloseList(final Query<T> query) {
        try {
            return new ArrayList<>(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    /**
     * Wrapper around {@link Query#executeResultUnique()} that closes the {@link Query}
     * after its result has been retrieved, to prevent resource leakage.
     *
     * @param query       The {@link Query} to execute
     * @param resultClass The {@link Class} of the {@link Query}'s result
     * @param <T>         Type of the {@link Query}'s result
     * @return The {@link Query}'s result
     */
    protected <T> T executeAndCloseResultUnique(final Query<?> query, final Class<T> resultClass) {
        try {
            return query.executeResultUnique(resultClass);
        } finally {
            query.closeAll();
        }
    }

    /**
     * Wrapper around {@link Query#executeResultList()} that closes the {@link Query}
     * after its result has been retrieved, to prevent resource leakage.
     *
     * @param query       The {@link Query} to execute
     * @param resultClass The {@link Class} of the {@link Query}'s result
     * @param <T>         Type of the {@link Query}'s result
     * @return The {@link Query}'s result
     */
    protected <T> List<T> executeAndCloseResultList(final Query<?> query, final Class<T> resultClass) {
        try {
            return new ArrayList<>(query.executeResultList(resultClass));
        } finally {
            query.closeAll();
        }
    }

}
