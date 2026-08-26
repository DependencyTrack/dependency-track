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

import org.postgresql.PGConnection;

import javax.sql.DataSource;
import java.io.Closeable;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;

/// A [DataSource] enforcing global query timeouts transparently.
///
/// @since 5.1.0
final class QueryTimeoutDataSource implements DataSource, Closeable {

    private final DataSource delegate;
    private final int timeoutSeconds;

    QueryTimeoutDataSource(DataSource delegate, int timeoutSeconds) {
        this.delegate = requireNonNull(delegate, "delegate must not be null");
        if (timeoutSeconds < 1) {
            throw new IllegalArgumentException("timeoutSeconds must not be less than 1");
        }
        this.timeoutSeconds = timeoutSeconds;
    }

    @Override
    public Connection getConnection() throws SQLException {
        return withQueryTimeout(delegate.getConnection());
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        return withQueryTimeout(delegate.getConnection(username, password));
    }

    @Override
    public void close() throws IOException {
        if (delegate instanceof Closeable closeable) {
            closeable.close();
        }
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        
        return delegate.unwrap(iface);
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
        return iface.isInstance(this) || delegate.isWrapperFor(iface);
    }

    @Override
    public PrintWriter getLogWriter() throws SQLException {
        return delegate.getLogWriter();
    }

    @Override
    public void setLogWriter(PrintWriter out) throws SQLException {
        delegate.setLogWriter(out);
    }

    @Override
    public void setLoginTimeout(int seconds) throws SQLException {
        delegate.setLoginTimeout(seconds);
    }

    @Override
    public int getLoginTimeout() throws SQLException {
        return delegate.getLoginTimeout();
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        return delegate.getParentLogger();
    }

    private Connection withQueryTimeout(Connection connection) throws SQLException {
        connection
                .unwrap(PGConnection.class)
                .setQueryTimeout(
                        !QueryTimeout.isBypassed()
                                ? timeoutSeconds
                                : 0);
        return connection;
    }

}
