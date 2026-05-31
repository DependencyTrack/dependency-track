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

import alpine.config.AlpineConfigKeys;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Utility class for working with HTTP proxies.
 *
 * @since 2.3.0
 */
public final class ProxyUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProxyUtil.class);

    private ProxyUtil() {
    }

    /**
     * Attempt to use application specific proxy settings if they exist.
     * Otherwise, attempt to use environment variables if they exist.
     * <p>
     * Ported from Dependency-Track's {@code ManagedHttpClientFactory}.
     *
     * @return A {@link ProxyConfig} object, or {@code null} if no proxy is configured
     * @see <a href="https://github.com/DependencyTrack/dependency-track/blob/4.7.0/src/main/java/org/dependencytrack/common/ManagedHttpClientFactory.java">Source</a>
     */
    @SuppressWarnings("unused")
    public static ProxyConfig getProxyConfig() {
        ProxyConfig proxyCfg = fromConfig(ConfigProvider.getConfig());
        if (proxyCfg == null) {
            proxyCfg = fromEnvironment(System.getenv());
        }
        return proxyCfg;
    }

    /**
     * Creates a {@link ProxyConfig} object from the application.properties configuration.
     * <p>
     * Ported from Dependency-Track's {@code ManagedHttpClientFactory}.
     *
     * @return A {@link ProxyConfig} object, or {@code null} if no proxy is configured
     * @see <a href="https://github.com/DependencyTrack/dependency-track/blob/4.7.0/src/main/java/org/dependencytrack/common/ManagedHttpClientFactory.java">Source</a>
     */
    static ProxyConfig fromConfig(final Config config) {
        if (config == null) {
            return null;
        }

        final String host = config.getOptionalValue(AlpineConfigKeys.HTTP_PROXY_HOST, String.class).orElse(null);
        if (host == null) {
            return null;
        }

        final Optional<Integer> port = config.getOptionalValue(AlpineConfigKeys.HTTP_PROXY_PORT, Integer.class);
        final String username = config.getOptionalValue(AlpineConfigKeys.HTTP_PROXY_USERNAME, String.class).orElse(null);
        final String password = config.getOptionalValue(AlpineConfigKeys.HTTP_PROXY_PASSWORD, String.class).orElse(null);
        final String noProxy = config.getOptionalValue(AlpineConfigKeys.NO_PROXY, String.class).orElse(null);

        final var proxyCfg = new ProxyConfig();
        proxyCfg.setHost(host);
        port.ifPresent(proxyCfg::setPort);

        if (username != null) {
            final Map.Entry<String, String> domainUsername = parseProxyUsername(username);
            Optional.ofNullable(domainUsername.getKey()).ifPresent(proxyCfg::setDomain);
            Optional.ofNullable(domainUsername.getValue()).ifPresent(proxyCfg::setUsername);
        }
        if (password != null) {
            proxyCfg.setPassword(password);
        }
        if (noProxy != null) {
            proxyCfg.setNoProxy(Set.of(noProxy.split(",")));
        }

        return proxyCfg;
    }

    /**
     * Creates a {@link ProxyConfig} object from the environment.
     * <p>
     * Ported from Dependency-Track's {@code ManagedHttpClientFactory}.
     *
     * @return A {@link ProxyConfig} object, or {@code null} if no proxy is configured
     * @see <a href="https://github.com/DependencyTrack/dependency-track/blob/4.7.0/src/main/java/org/dependencytrack/common/ManagedHttpClientFactory.java">Source</a>
     */
    static ProxyConfig fromEnvironment(final Map<String, String> env) {
        ProxyConfig proxyCfg = null;
        try {
            proxyCfg = buildFromEnvironment(env, "https_proxy");
            if (proxyCfg == null) {
                proxyCfg = buildFromEnvironment(env, "http_proxy");
            }
        } catch (MalformedURLException | SecurityException | UnsupportedEncodingException e) {
            LOGGER.warn("Could not parse proxy settings from environment", e);
        }

        if (proxyCfg != null) {
            for (Map.Entry<String, String> entry : env.entrySet()) {
                if ("no_proxy".equalsIgnoreCase(entry.getKey().toUpperCase())) {
                    proxyCfg.setNoProxy(Set.of(entry.getValue().split(",")));
                    break;
                }
            }
        }

        return proxyCfg;
    }

    /**
     * Retrieves and parses the {@code https_proxy} and {@code http_proxy} settings.
     * This method ignores the case of the variables in the environment.
     * <p>
     * Ported from Dependency-Track's {@code ManagedHttpClientFactory}.
     *
     * @param variable the name of the environment variable
     * @return a {@link ProxyConfig} object, or {@code null} if proxy is not defined
     * @throws MalformedURLException if the URL of the proxy setting cannot be parsed
     * @throws SecurityException     if the environment variable cannot be retrieved
     * @see <a href="https://github.com/DependencyTrack/dependency-track/blob/4.7.0/src/main/java/org/dependencytrack/common/ManagedHttpClientFactory.java">Source</a>
     */
    private static ProxyConfig buildFromEnvironment(final Map<String, String> env, final String variable)
            throws MalformedURLException, UnsupportedEncodingException {
        if (env == null || variable == null) {
            return null;
        }

        String proxy = null;
        for (Map.Entry<String, String> entry : env.entrySet()) {
            if (variable.equalsIgnoreCase(entry.getKey().toUpperCase())) {
                proxy = entry.getValue();
                break;
            }
        }
        if (proxy == null) {
            return null;
        }

        final var proxyUrl = URI.create(proxy).toURL();
        final var proxyCfg = new ProxyConfig();
        proxyCfg.setHost(proxyUrl.getHost());
        proxyCfg.setPort(proxyUrl.getPort());

        if (proxyUrl.getUserInfo() != null) {
            final String[] credentials = proxyUrl.getUserInfo().split(":");
            if (credentials.length > 0) {
                final String username = URLDecoder.decode(credentials[0], StandardCharsets.UTF_8);
                final Map.Entry<String, String> domainUsername = parseProxyUsername(username);
                Optional.ofNullable(domainUsername.getKey()).ifPresent(proxyCfg::setDomain);
                Optional.ofNullable(domainUsername.getValue()).ifPresent(proxyCfg::setUsername);
            }
            if (credentials.length == 2) {
                proxyCfg.setPassword(URLDecoder.decode(credentials[1], StandardCharsets.UTF_8));
            }
        }

        return proxyCfg;
    }

    /**
     * Optionally parses usernames if they are NTLM formatted.
     * <p>
     * Ported from Dependency-Track's {@code ManagedHttpClientFactory}.
     *
     * @param username The username to parse
     * @return A {@link Map.Entry} consisting of the user's domain (if any), and the username
     * @see <a href="https://github.com/DependencyTrack/dependency-track/blob/4.7.0/src/main/java/org/dependencytrack/common/ManagedHttpClientFactory.java">Source</a>
     */
    private static Map.Entry<String, String> parseProxyUsername(final String username) {
        if (username.contains("\\")) {
            return new AbstractMap.SimpleEntry<>(
                    username.substring(0, username.indexOf("\\")),
                    username.substring(username.indexOf("\\") + 1)
            );
        }
        return new AbstractMap.SimpleEntry<>(null, username);
    }

}
