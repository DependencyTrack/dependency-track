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
package alpine.server.persistence;

import alpine.persistence.IPersistenceManagerFactory;
import alpine.persistence.JdoProperties;
import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Metrics;
import io.smallrye.config.SmallRyeConfig;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.datanucleus.PropertyNames;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jdo.JDOHelper;
import javax.jdo.PersistenceManager;
import javax.sql.DataSource;
import java.util.Properties;

/**
 * Initializes the JDO persistence manager on server startup.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class PersistenceManagerFactory implements IPersistenceManagerFactory, ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(PersistenceManagerFactory.class);
    private static final String DATANUCLEUS_METRICS_PREFIX = "datanucleus_";

    private static JDOPersistenceManagerFactory pmf;

    @Override
    public void contextInitialized(ServletContextEvent event) {
        LOGGER.info("Initializing persistence framework");

        final var dnProps = new Properties();

        // Apply settings that are required by Alpine and shouldn't be customized.
        dnProps.put(PropertyNames.PROPERTY_CACHE_L2_TYPE, "none");
        dnProps.put(PropertyNames.PROPERTY_QUERY_JDOQL_ALLOWALL, "true");
        dnProps.put(PropertyNames.PROPERTY_RETAIN_VALUES, "true");
        dnProps.put(PropertyNames.PROPERTY_METADATA_ALLOW_XML, "false");
        dnProps.put(PropertyNames.PROPERTY_METADATA_SUPPORT_ORM, "false");
        dnProps.put(PropertyNames.PROPERTY_ENABLE_STATISTICS, "true");
        dnProps.put(PropertyNames.PROPERTY_EXECUTION_CONTEXT_MAX_IDLE, "0");
        dnProps.put(PropertyNames.PROPERTY_DELETION_POLICY, "DataNucleus");

        final DataSource dataSource = DataSourceRegistry.getInstance().getDefault();
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_FACTORY, dataSource);
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_FACTORY2, dataSource);

        pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(dnProps, "Alpine");
        registerDataNucleusMetrics(pmf);
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        LOGGER.info("Shutting down persistence framework");
        tearDown();
    }

    /**
     * Creates a new JDO PersistenceManager.
     *
     * @return a PersistenceManager
     */
    public static PersistenceManager createPersistenceManager() {
        if (pmf == null && ConfigProvider.getConfig().unwrap(SmallRyeConfig.class).getProfiles().contains("test")) {
            pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(JdoProperties.unit(), "Alpine");
        }
        if (pmf == null) {
            throw new IllegalStateException("Context is not initialized yet.");
        }
        return pmf.getPersistenceManager();
    }

    public PersistenceManager getPersistenceManager() {
        return createPersistenceManager();
    }


    /**
     * Set the {@link JDOPersistenceManagerFactory} to be used by {@link PersistenceManagerFactory}.
     * <p>
     * This is mainly useful for integration tests that run outside a servlet context,
     * yet require a persistence context setup with an external database.
     *
     * @param pmf The {@link JDOPersistenceManagerFactory} to set
     * @throws IllegalStateException When the {@link JDOPersistenceManagerFactory} was already initialized
     * @since 2.1.0
     */
    @SuppressWarnings("unused")
    public static void setJdoPersistenceManagerFactory(final JDOPersistenceManagerFactory pmf) {
        if (PersistenceManagerFactory.pmf != null) {
            throw new IllegalStateException("The PersistenceManagerFactory can only be set when it hasn't been initialized yet.");
        }

        PersistenceManagerFactory.pmf = pmf;
    }

    /**
     * Closes the {@link JDOPersistenceManagerFactory} and removes any reference to it.
     * <p>
     * This method should be called in the {@code tearDown} method of unit- and integration
     * tests that interact with the persistence layer.
     *
     * @since 2.1.0
     */
    public static void tearDown() {
        if (pmf != null) {
            pmf.close();
            pmf = null;
        }
    }

    private void registerDataNucleusMetrics(final JDOPersistenceManagerFactory pmf) {
        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "datastore_reads_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getNumberOfDatastoreReads())
                .description("Total number of read operations from the datastore")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "datastore_writes_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getNumberOfDatastoreWrites())
                .description("Total number of write operations to the datastore")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "object_fetches_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getNumberOfObjectFetches())
                .description("Total number of objects fetched from the datastore")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "object_inserts_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getNumberOfObjectInserts())
                .description("Total number of objects inserted into the datastore")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "object_updates_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getNumberOfObjectUpdates())
                .description("Total number of objects updated in the datastore")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "object_deletes_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getNumberOfObjectDeletes())
                .description("Total number of objects deleted from the datastore")
                .register(Metrics.globalRegistry);

        Gauge.builder(DATANUCLEUS_METRICS_PREFIX + "query_execution_time_ms_avg", pmf,
                        p -> p.getNucleusContext().getStatistics().getQueryExecutionTimeAverage())
                .description("Average query execution time in milliseconds")
                .register(Metrics.globalRegistry);

        Gauge.builder(DATANUCLEUS_METRICS_PREFIX + "queries_active", pmf,
                        p -> p.getNucleusContext().getStatistics().getQueryActiveTotalCount())
                .description("Number of currently active queries")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "queries_executed_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getQueryExecutionTotalCount())
                .description("Total number of executed queries")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "queries_failed_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getQueryErrorTotalCount())
                .description("Total number of queries that completed with an error")
                .register(Metrics.globalRegistry);

        Gauge.builder(DATANUCLEUS_METRICS_PREFIX + "transaction_execution_time_ms_avg", pmf,
                        p -> p.getNucleusContext().getStatistics().getTransactionExecutionTimeAverage())
                .description("Average transaction execution time in milliseconds")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "transactions_active", pmf,
                        p -> p.getNucleusContext().getStatistics().getTransactionActiveTotalCount())
                .description("Number of currently active transactions")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "transactions_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getTransactionTotalCount())
                .description("Total number of transactions")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "transactions_committed_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getTransactionCommittedTotalCount())
                .description("Total number of committed transactions")
                .register(Metrics.globalRegistry);

        FunctionCounter.builder(DATANUCLEUS_METRICS_PREFIX + "transactions_rolledback_total", pmf,
                        p -> p.getNucleusContext().getStatistics().getTransactionRolledBackTotalCount())
                .description("Total number of rolled-back transactions")
                .register(Metrics.globalRegistry);

        // This number does not necessarily equate the number of physical connections.
        // It resembles the number of active connections MANAGED BY DATANUCLEUS.
        // The number of connections reported by connection pool metrics will differ.
        Gauge.builder(DATANUCLEUS_METRICS_PREFIX + "connections_active", pmf,
                        p -> p.getNucleusContext().getStatistics().getConnectionActiveCurrent())
                .description("Number of currently active managed datastore connections")
                .register(Metrics.globalRegistry);

        Gauge.builder(DATANUCLEUS_METRICS_PREFIX + "cache_second_level_entries", pmf,
                        p -> p.getNucleusContext().getLevel2Cache().getSize())
                .description("Number of entries in the second level cache")
                .register(Metrics.globalRegistry);

        Gauge.builder(DATANUCLEUS_METRICS_PREFIX + "cache_query_generic_compilation_entries", pmf,
                        p -> p.getQueryGenericCompilationCache().size())
                .description("Number of entries in the generic query compilation cache")
                .register(Metrics.globalRegistry);

        Gauge.builder(DATANUCLEUS_METRICS_PREFIX + "cache_query_datastore_compilation_entries", pmf,
                        p -> p.getQueryDatastoreCompilationCache().size())
                .description("Number of entries in the datastore query compilation cache")
                .register(Metrics.globalRegistry);

        // Note: The query results cache is disabled per default.
        Gauge.builder(DATANUCLEUS_METRICS_PREFIX + "cache_query_result_entries", pmf,
                        p -> p.getQueryCache().getQueryCache().size())
                .description("Number of entries in the query result cache")
                .register(Metrics.globalRegistry);
    }

}
