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
package alpine.server.auth;

import javax.sql.DataSource;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.util.concurrent.atomic.AtomicInteger;

final class CountingDataSource {

    private CountingDataSource() {}

    static DataSource wrap(DataSource delegate, AtomicInteger statementCount) {
        final InvocationHandler dataSourceHandler = (_, method, args) -> {
            final Object result = method.invoke(delegate, args);
            if (!"getConnection".equals(method.getName())) {
                return result;
            }

            final InvocationHandler connectionHandler = (_, connectionMethod, connectionArgs) -> {
                if (connectionMethod.getName().startsWith("prepare")
                        || "createStatement".equals(connectionMethod.getName())) {
                    statementCount.incrementAndGet();
                }
                return connectionMethod.invoke(result, connectionArgs);
            };

            return Proxy.newProxyInstance(
                    CountingDataSource.class.getClassLoader(), new Class<?>[] {Connection.class}, connectionHandler);
        };

        return (DataSource) Proxy.newProxyInstance(
                CountingDataSource.class.getClassLoader(), new Class<?>[] {DataSource.class}, dataSourceHandler);
    }
}
