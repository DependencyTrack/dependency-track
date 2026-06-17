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
package alpine.common.util;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.util.Set;

/**
 * HTTP proxy configuration.
 * <p>
 * Ported from Dependency-Track's {@code ManagedHttpClientFactory}.
 *
 * @see <a href="https://github.com/DependencyTrack/dependency-track/blob/4.7.0/src/main/java/org/dependencytrack/common/ManagedHttpClientFactory.java">Source</a>
 * @since 2.3.0
 */
public final class ProxyConfig {

    private String host;
    private int port;
    private String domain;
    private String username;
    private String password;
    private Set<String> noProxy;

    /**
     * Determines if proxy should be used or not for a given {@link URI}.
     * <p>
     * Ported from Dependency-Track's {@code ManagedHttpClientFactory}.
     *
     * @param uri the URL that is being called by this application
     * @return {@code true} if proxy is to be used, {@code false} if not
     * @see <a href="https://github.com/DependencyTrack/dependency-track/blob/4.7.0/src/main/java/org/dependencytrack/common/ManagedHttpClientFactory.java">Source</a>
     */
    public boolean shouldProxy(final URL uri) {
        if (host == null || uri == null || !Set.of("http", "https").contains(uri.getProtocol())) {
            return false;
        }
        if (noProxy == null) {
            return true;
        }
        if (noProxy.contains("*")) {
            return false;
        }

        final String hostname = uri.getHost();
        int hostPort = uri.getPort();

        for (final String bypassURL : noProxy) {
            final String[] bypassURLList = bypassURL.split(":");
            final String byPassHost = bypassURLList[0];
            int byPassPort = -1;
            if (bypassURLList.length == 2) {
                byPassPort = Integer.parseInt(bypassURLList[1]);
            }
            if (hostPort == byPassPort || byPassPort == -1) {
                if (hostname.equalsIgnoreCase(byPassHost)) {
                    return false;
                }
                int hl = hostname.length();
                int bl = byPassHost.length();
                if (hl > bl && hostname.substring(hl - bl - 1).equalsIgnoreCase("." + byPassHost)) {
                    return false;
                }
            }
        }
        return true;
    }

    public Proxy getProxy() {
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
    }

    public String getHost() {
        return host;
    }

    public void setHost(final String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(final int port) {
        this.port = port;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(final String domain) {
        this.domain = domain;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    public Set<String> getNoProxy() {
        return noProxy;
    }

    public void setNoProxy(final Set<String> noProxy) {
        this.noProxy = noProxy;
    }

}
