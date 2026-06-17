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
package org.dependencytrack.common;

import alpine.common.util.ProxyConfig;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.util.List;

/**
 * A {@link ProxySelector} based on Alpine's {@link ProxyConfig}.
 * <p>
 * TODO: Move this to Alpine.
 *
 * @since 4.10.0
 */
public class AlpineHttpProxySelector extends ProxySelector {

    private final ProxyConfig proxyConfig;

    public AlpineHttpProxySelector(final ProxyConfig proxyConfig) {
        this.proxyConfig = proxyConfig;
    }

    @Override
    public List<Proxy> select(final URI uri) {
        if (!"http".equals(uri.getScheme()) && !"https".equals(uri.getScheme())) {
            return List.of(Proxy.NO_PROXY);
        }

        if (proxyConfig == null) {
            return List.of(Proxy.NO_PROXY);
        }

        final URL url;
        try {
            url = uri.toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException("Failed to construct URL from %s".formatted(uri), e);
        }

        if (!proxyConfig.shouldProxy(url)) {
            return List.of(Proxy.NO_PROXY);
        }

        return List.of(proxyConfig.getProxy());
    }

    @Override
    public void connectFailed(final URI uri, final SocketAddress sa, final IOException ioe) {
    }

}
