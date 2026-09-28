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
package org.dependencytrack.persistence.jdbi;

import alpine.resources.AlpineRequest;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.micrometer.core.instrument.Metrics;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.common.pagination.SimplePageTokenEncoder;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.mapping.ExternalReferencesColumnMapper;
import org.dependencytrack.persistence.jdbi.mapping.OrganizationalContactsColumnMapper;
import org.dependencytrack.persistence.jdbi.mapping.OrganizationalEntityColumnMapper;
import org.dependencytrack.persistence.jdbi.mapping.PackageArtifactMetadataRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.PackageMetadataRowMapper;
import org.dependencytrack.support.jdbi.exception.ExceptionTranslationPlugin;
import org.dependencytrack.support.jdbi.mapping.DateColumnMapper;
import org.dependencytrack.support.jdbi.mapping.PurlColumnMapper;
import org.jdbi.v3.core.ConnectionFactory;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.HandleCallback;
import org.jdbi.v3.core.HandleConsumer;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.Cleanable;
import org.jdbi.v3.freemarker.FreemarkerConfig;
import org.jdbi.v3.freemarker.FreemarkerEngine;
import org.jdbi.v3.jackson2.Jackson2Config;
import org.jdbi.v3.jackson2.Jackson2Plugin;
import org.jdbi.v3.postgres.PostgresPlugin;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;

import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.datastore.JDOConnection;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;

public class JdbiFactory {

    private static final AtomicReference<GlobalInstanceHolder> GLOBAL_INSTANCE_HOLDER = new AtomicReference<>();
    private static final ScopedValue<Connection> JDO_CONNECTION = ScopedValue.newInstance();

    public static Handle openJdbiHandle() {
        return createJdbi().open();
    }

    public static Handle openJdbiHandle(final AlpineRequest alpineRequest) {
        return forApiRequest(createJdbi().open(), alpineRequest);
    }

    public static <X extends Exception> void useJdbiHandle(final HandleConsumer<X> handleConsumer) throws X {
        useJdbiHandle((AlpineRequest) null, handleConsumer);
    }

    public static <X extends Exception> void useJdbiHandle(
            final AlpineRequest apiRequest, final HandleConsumer<X> handleConsumer) throws X {
        createJdbi().useHandle(handle -> handleConsumer.useHandle(forApiRequest(handle, apiRequest)));
    }

    public static <T, X extends Exception> T withJdbiHandle(final HandleCallback<T, X> handleCallback) throws X {
        return withJdbiHandle((AlpineRequest) null, handleCallback);
    }

    public static <T, X extends Exception> T withJdbiHandle(
            final AlpineRequest apiRequest, final HandleCallback<T, X> handleCallback) throws X {
        return createJdbi().withHandle(handle -> handleCallback.withHandle(forApiRequest(handle, apiRequest)));
    }

    /// @since 5.2.0
    public static <X extends Exception> void useJdbiHandle(QueryManager qm, HandleConsumer<X> handleConsumer) throws X {
        withJdbiHandle(qm, handleConsumer.asCallback());
    }

    /// Joins the active transaction of `qm`, if any. Don't use `qm` within `handleCallback`,
    /// and don't expect JDO objects loaded earlier to reflect what `handleCallback` wrote.
    ///
    /// @since 5.2.0
    public static <T, X extends Exception> T withJdbiHandle(QueryManager qm, HandleCallback<T, X> handleCallback)
            throws X {
        final PersistenceManager pm = qm.getPersistenceManager();
        if (!pm.currentTransaction().isActive()) {
            // DataNucleus commits its non-transactional connection on release, even if handleCallback failed.
            // There's no point in reusing the PM's connection anyway since DN releases connections after each
            // statement outside of transactions.
            return withJdbiHandle(qm.getAlpineRequest(), handleCallback);
        }

        // Jdbi#withHandle would reuse the thread's open handle, which doesn't use the PM's connection.
        if (createJdbi().getHandleScope().get() != null) {
            throw new IllegalStateException("Can't use the connection of a PersistenceManager within another handle");
        }

        // Ensure that all changes made by JDO are visible in the database
        // as JDBI would otherwise be blind to them.
        pm.flush();

        final JDOConnection jdoConnection = pm.getDataStoreConnection();
        try {
            return ScopedValue.where(JDO_CONNECTION, (Connection) jdoConnection.getNativeConnection())
                    .call(() -> withJdbiHandle(qm.getAlpineRequest(), handleCallback));
        } finally {
            jdoConnection.close();
        }
    }

    public static <X extends Exception> void useJdbiTransaction(final HandleConsumer<X> handleConsumer) throws X {
        useJdbiTransaction(/* apiRequest */ null, handleConsumer);
    }

    public static <X extends Exception> void useJdbiTransaction(
            final AlpineRequest apiRequest, final HandleConsumer<X> handleConsumer) throws X {
        createJdbi().useTransaction(handle -> handleConsumer.useHandle(forApiRequest(handle, apiRequest)));
    }

    public static <T, X extends Exception> T inJdbiTransaction(final HandleCallback<T, X> handleCallback) throws X {
        return inJdbiTransaction(/* apiRequest */ null, handleCallback);
    }

    public static <T, X extends Exception> T inJdbiTransaction(
            final AlpineRequest apiRequest, final HandleCallback<T, X> handleCallback) throws X {
        return createJdbi().inTransaction(handle -> handleCallback.withHandle(forApiRequest(handle, apiRequest)));
    }

    private static Handle forApiRequest(final Handle handle, final AlpineRequest apiRequest) {
        if (apiRequest != null) {
            handle.getConfig(ApiRequestConfig.class).setApiRequest(apiRequest);
        }

        return handle.addCustomizer(new ApiRequestStatementCustomizer());
    }

    /**
     * Get a global {@link Jdbi} instance, initializing it if it hasn't been initialized before.
     * <p>
     * The global instance will use {@link Connection}s from the primary {@link DataSource}
     * of a {@link PersistenceManager}'s {@link PersistenceManagerFactory}.
     * <p>
     * Usage of the global instance should be preferred to make the best possible use of JDBI's
     * internal caching mechanisms. Handles participate in transactions initiated by JDO
     * (via {@link QueryManager} or {@link PersistenceManager}) only when obtained through
     * {@link #withJdbiHandle(QueryManager, HandleCallback)}.
     *
     * @return The global {@link Jdbi} instance
     */
    // Detects a replaced DataSource instance, so identity is what matters.
    @SuppressWarnings("ReferenceEquality")
    public static Jdbi createJdbi() {
        return GLOBAL_INSTANCE_HOLDER
                .updateAndGet(previous -> {
                    final DataSource dataSource =
                            DataSourceRegistry.getInstance().getDefault();
                    if (previous == null || previous.dataSource() != dataSource) {
                        // The PMF reference does not usually change, unless it has been recreated,
                        // or multiple PMFs exist in the same application. The latter is not the case
                        // for Dependency-Track, and the former only happens during test execution,
                        // where each test (re-)creates the PMF.
                        final Jdbi jdbi = customizeJdbi(Jdbi.create(new GlobalConnectionFactory(dataSource)));
                        return new GlobalInstanceHolder(jdbi, dataSource);
                    }

                    return previous;
                })
                .jdbi();
    }

    public static Jdbi createLocalJdbi(final DataSource dataSource) {
        return customizeJdbi(Jdbi.create(dataSource));
    }

    private record GlobalInstanceHolder(Jdbi jdbi, DataSource dataSource) {}

    private record GlobalConnectionFactory(DataSource dataSource) implements ConnectionFactory {

        @Override
        public Connection openConnection() throws SQLException {
            return JDO_CONNECTION.isBound() ? JDO_CONNECTION.get() : dataSource.getConnection();
        }

        @Override
        public Cleanable getCleanableFor(Connection connection) {
            // NB: JDO owns the borrowed connection, it's returned via JDOConnection#close.
            return JDO_CONNECTION.isBound() ? () -> {} : connection::close;
        }
    }

    private static Jdbi customizeJdbi(final Jdbi jdbi) {
        final Jdbi preparedJdbi = jdbi.installPlugin(new SqlObjectPlugin())
                .installPlugin(new PostgresPlugin())
                .installPlugin(new Jackson2Plugin())
                .installPlugin(new ExceptionTranslationPlugin())
                .setTemplateEngine(FreemarkerEngine.instance())
                .setSqlLogger(new QueryTimingSqlLogger(Metrics.globalRegistry))
                .registerArrayType(Date.class, "TIMESTAMPTZ")
                .registerArrayType(Timestamp.class, "TIMESTAMPTZ")
                .registerColumnMapper(new DateColumnMapper())
                .registerColumnMapper(new ExternalReferencesColumnMapper())
                .registerColumnMapper(new OrganizationalContactsColumnMapper())
                .registerColumnMapper(new OrganizationalEntityColumnMapper())
                .registerColumnMapper(new PurlColumnMapper())
                .registerRowMapper(new PackageMetadataRowMapper())
                .registerRowMapper(new PackageArtifactMetadataRowMapper());

        preparedJdbi.getConfig(PaginationConfig.class).setPageTokenEncoder(new SimplePageTokenEncoder());
        preparedJdbi.getConfig(Jackson2Config.class).setMapper(createJsonMapper());
        preparedJdbi
                .getConfig(FreemarkerConfig.class)
                .getFreemarkerConfiguration()
                .addAutoImport("sql", "ftl/sql-macros.ftl");
        return preparedJdbi;
    }

    private static JsonMapper createJsonMapper() {
        return JsonMapper.builder()
                // Avoid unnecessary @JsonAlias or "SELECT ... AS ..." statements
                // for mapping upper-cased columns to camel-cased Java fields.
                .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES)
                .addModule(new JavaTimeModule())
                .build();
    }
}
