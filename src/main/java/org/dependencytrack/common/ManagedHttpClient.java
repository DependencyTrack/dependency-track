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
package org.dependencytrack.common;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

public class ManagedHttpClient {

    private CloseableHttpClient httpClient;
    private PoolingHttpClientConnectionManager connectionManager;

    public ManagedHttpClient(CloseableHttpClient httpClient, PoolingHttpClientConnectionManager connectionManager) {
        this.httpClient = httpClient;
        this.connectionManager = connectionManager;
    }

    public CloseableHttpClient getHttpClient() {
        return httpClient;
    }

    public PoolingHttpClientConnectionManager getConnectionManager() {
        return connectionManager;
    }
}
