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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.util.SystemUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.auth.AuthSchemeFactory;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.NTCredentials;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.DefaultAuthenticationStrategy;
import org.apache.hc.client5.http.impl.DefaultRedirectStrategy;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.auth.BasicSchemeFactory;
import org.apache.hc.client5.http.impl.auth.DigestSchemeFactory;
import org.apache.hc.client5.http.impl.auth.NTLMSchemeFactory;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.routing.DefaultProxyRoutePlanner;
import org.apache.hc.client5.http.routing.HttpRoutePlanner;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.config.Lookup;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;

import javax.net.ssl.SSLContext;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;

public final class ManagedHttpClientFactory {

    private static final String PROXY_ADDRESS = Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_ADDRESS);
    private static int PROXY_PORT;

    static {
        if (PROXY_ADDRESS != null) {
            PROXY_PORT = Config.getInstance().getPropertyAsInt(Config.AlpineKey.HTTP_PROXY_PORT);
        }
    }

    private static final String PROXY_USERNAME = Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_USERNAME);
    private static final String PROXY_PASSWORD = Config.getInstance().getPropertyOrFile(Config.AlpineKey.HTTP_PROXY_PASSWORD);
    private static final String NO_PROXY = Config.getInstance().getProperty(Config.AlpineKey.NO_PROXY);
    private static final int TIMEOUT_CONNECTION = Config.getInstance().getPropertyAsInt(Config.AlpineKey.HTTP_TIMEOUT_CONNECTION);
    private static final int TIMEOUT_POOL = Config.getInstance().getPropertyAsInt(Config.AlpineKey.HTTP_TIMEOUT_POOL);
    private static final int TIMEOUT_SOCKET = Config.getInstance().getPropertyAsInt(Config.AlpineKey.HTTP_TIMEOUT_SOCKET);
    private static final Logger LOGGER = Logger.getLogger(ManagedHttpClientFactory.class);
    private static final String USER_AGENT;

    static {
        USER_AGENT = Config.getInstance().getApplicationName()
                + " v" + Config.getInstance().getApplicationVersion()
                + " ("
                + SystemUtil.getOsArchitecture() + "; "
                + SystemUtil.getOsName() + "; "
                + SystemUtil.getOsVersion()
                + ") ManagedHttpClient/"
                + Config.getInstance().getSystemUuid();
    }

    private ManagedHttpClientFactory() {
    }

    public static String getUserAgent() {
        return USER_AGENT;
    }

    /**
     * Factory method that create a PooledHttpClient object. This method will attempt to use
     * proxy settings defined in application.properties first. If they are not set,
     * this method will attempt to use proxy settings from the environment by looking
     * for 'https_proxy', 'http_proxy' and 'no_proxy'.
     *
     * @return a PooledHttpClient object with optional proxy settings
     */
    public static ManagedHttpClient newManagedHttpClient() {
        PoolingHttpClientConnectionManager connectionManager = null;
        final RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.ofSeconds(TIMEOUT_POOL))
                .build();
        final ConnectionConfig connectionConfig = ConnectionConfig.custom()
                .setConnectTimeout(Timeout.ofSeconds(TIMEOUT_CONNECTION))
                .build();
        final SocketConfig socketConfig = SocketConfig.custom()
                .setSoTimeout(Timeout.ofSeconds(TIMEOUT_SOCKET))
                .build();
        final HttpClientBuilder clientBuilder = HttpClients.custom().setDefaultRequestConfig(requestConfig);
        final var credsProvider = new BasicCredentialsProvider();
        clientBuilder.useSystemProperties();

        final ProxyInfo proxyInfo = createProxyInfo();

        if (proxyInfo != null) {
            HttpRoutePlanner routePlanner = new DefaultProxyRoutePlanner(new HttpHost(proxyInfo.host, proxyInfo.port)) {
                @Override
                protected HttpHost determineProxy(final HttpHost target, final HttpContext context) throws HttpException {
                    if (isProxy(proxyInfo.noProxy, target)) {
                        return super.determineProxy(target, context);
                    }

                    return target;
                }
            };
            clientBuilder.setRoutePlanner(routePlanner);
            if (StringUtils.isNotBlank(proxyInfo.username) && StringUtils.isNotBlank(proxyInfo.password)) {
                final var authScopeAny = new AuthScope(null, null, -1, null, null);
                if (proxyInfo.domain != null) {
                    credsProvider.setCredentials(authScopeAny, new NTCredentials(proxyInfo.username, proxyInfo.password.toCharArray(), proxyInfo.domain, null));
                } else {
                    credsProvider.setCredentials(authScopeAny, new UsernamePasswordCredentials(proxyInfo.username, proxyInfo.password.toCharArray()));
                }
            }
        }
        // When a proxy is enabled, turn off certificate chain of trust validation and hostname verification
        if (proxyInfo != null && proxyInfo.noProxy == null) {
            try {
                final SSLContext sslContext = SSLContextBuilder
                        .create()
                        .loadTrustMaterial(new TrustAllStrategy())
                        .build();
                final Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("http", PlainConnectionSocketFactory.INSTANCE)
                        .register("https", new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE))
                        .build();
                connectionManager = new PoolingHttpClientConnectionManager(registry);
                connectionManager.setMaxTotal(200);
                connectionManager.setDefaultMaxPerRoute(20);
                connectionManager.setDefaultConnectionConfig(connectionConfig);
                connectionManager.setDefaultSocketConfig(socketConfig);
                clientBuilder.setConnectionManager(connectionManager);
                clientBuilder.setConnectionManagerShared(true);
            } catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException e) {
                LOGGER.warn("An error occurred while configuring proxy", e);
            }
        } else {
            connectionManager = new PoolingHttpClientConnectionManager();
            connectionManager.setMaxTotal(200);
            connectionManager.setDefaultMaxPerRoute(20);
            connectionManager.setDefaultConnectionConfig(connectionConfig);
            connectionManager.setDefaultSocketConfig(socketConfig);
            clientBuilder.setConnectionManager(connectionManager);
        }

        clientBuilder.setDefaultCredentialsProvider(credsProvider);
        clientBuilder.setProxyAuthenticationStrategy(new DefaultAuthenticationStrategy());
        final Lookup<AuthSchemeFactory> authProviders = RegistryBuilder.<AuthSchemeFactory>create()
                .register(StandardAuthScheme.BASIC, BasicSchemeFactory.INSTANCE)
                .register(StandardAuthScheme.DIGEST, DigestSchemeFactory.INSTANCE)
                .register(StandardAuthScheme.NTLM, NTLMSchemeFactory.INSTANCE)
                .build();
        clientBuilder.setDefaultAuthSchemeRegistry(authProviders);
        clientBuilder.disableCookieManagement();
        clientBuilder.setRedirectStrategy(DefaultRedirectStrategy.INSTANCE);
        return new ManagedHttpClient(clientBuilder.build(), connectionManager);
    }

    /**
     * Determines if proxy should be used or not for a given URL
     *
     * @param noProxyList list of URLs to be exempted from proxy
     * @param host        the URL that is being called by this application
     * @return true if proxy is to be be used, false if not
     */
    public static boolean isProxy(String[] noProxyList, HttpHost host) {
        if (noProxyList == null) {
            return true;
        }
        if (Arrays.equals(noProxyList, new String[]{"*"})) {
            return false;
        }
        String hostname = host.getHostName();
        int hostPort = host.getPort();
        for (String bypassURL : noProxyList) {
            String[] bypassURLList = bypassURL.split(":");
            String byPassHost = bypassURLList[0];
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

    /**
     * Attempt to use application specific proxy settings if they exist.
     * Otherwise, attempt to use environment variables if they exist.
     *
     * @return ProxyInfo object, or null if proxy is not configured
     */
    public static ProxyInfo createProxyInfo() {
        ProxyInfo proxyInfo = fromConfig();
        if (proxyInfo == null) {
            proxyInfo = fromEnvironment();
        }
        return proxyInfo;
    }

    /**
     * Creates a ProxyInfo object from the application.properties configuration.
     *
     * @return a ProxyInfo object, or null if proxy is not configured
     */
    private static ProxyInfo fromConfig() {
        ProxyInfo proxyInfo = null;
        if (PROXY_ADDRESS != null) {
            proxyInfo = new ProxyInfo();
            proxyInfo.host = StringUtils.trimToNull(PROXY_ADDRESS);
            proxyInfo.port = PROXY_PORT;
            if (PROXY_USERNAME != null) {
                parseProxyUsername(proxyInfo, PROXY_USERNAME);
            }
            if (PROXY_PASSWORD != null) {
                proxyInfo.password = StringUtils.trimToNull(PROXY_PASSWORD);
            }
            if (NO_PROXY != null) {
                proxyInfo.noProxy = NO_PROXY.split(",");
            }
        }
        return proxyInfo;
    }

    /**
     * Creates a ProxyInfo object from the environment.
     *
     * @return a ProxyInfo object, or null if proxy is not defined
     */
    private static ProxyInfo fromEnvironment() {
        ProxyInfo proxyInfo = null;
        try {
            proxyInfo = buildfromEnvironment("https_proxy");
            if (proxyInfo == null) {
                proxyInfo = buildfromEnvironment("http_proxy");
            }
        } catch (MalformedURLException | SecurityException | UnsupportedEncodingException e) {
            LOGGER.warn("Could not parse proxy settings from environment", e);
        }
        if (proxyInfo != null) {
            for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
                if ("NO_PROXY".equals(entry.getKey().toUpperCase())) {
                    proxyInfo.noProxy = System.getenv(entry.getKey()).split(",");
                    break;
                }
            }
        }
        return proxyInfo;
    }

    /**
     * Retrieves and parses the https_proxy and http_proxy settings. This method ignores the
     * case of the variables in the environment.
     *
     * @param variable the name of the environment variable
     * @return a ProxyInfo object, or null if proxy is not defined
     * @throws MalformedURLException if the URL of the proxy setting cannot be parsed
     * @throws SecurityException     if the environment variable cannot be retrieved
     */
    private static ProxyInfo buildfromEnvironment(final String variable)
            throws MalformedURLException, SecurityException, UnsupportedEncodingException {

        if (variable == null) {
            return null;
        }
        ProxyInfo proxyInfo = null;

        String proxy = null;
        for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
            if (variable.toUpperCase().equals(entry.getKey().toUpperCase())) {
                proxy = System.getenv(entry.getKey());
                break;
            }
        }

        if (proxy != null) {
            final URL proxyUrl = new URL(proxy);
            proxyInfo = new ProxyInfo();
            proxyInfo.host = proxyUrl.getHost();
            proxyInfo.port = proxyUrl.getPort();
            if (proxyUrl.getUserInfo() != null) {
                final String[] credentials = proxyUrl.getUserInfo().split(":");
                if (credentials.length > 0) {
                    final String username = URLDecoder.decode(credentials[0], "UTF-8");
                    parseProxyUsername(proxyInfo, username);
                }
                if (credentials.length == 2) {
                    proxyInfo.password = URLDecoder.decode(credentials[1], "UTF-8");
                }
            }
        }
        return proxyInfo;
    }

    /**
     * Optionally parses usernames if they are NTLM formatted.
     *
     * @param proxyInfo The ProxyInfo object to update from the result of parsing
     * @param username  The username to parse
     */
    @SuppressWarnings("deprecation")
    private static void parseProxyUsername(final ProxyInfo proxyInfo, final String username) {
        if (username.contains("\\")) {
            proxyInfo.domain = username.substring(0, username.indexOf("\\"));
            proxyInfo.username = username.substring(username.indexOf("\\") + 1);
        } else {
            proxyInfo.username = username;
        }
    }

    /**
     * A simple holder class for proxy configuration.
     */
    public static class ProxyInfo {
        private String host;
        private int port;
        private String domain;
        private String username;
        private String password;
        private String[] noProxy;

        public String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }

        public String getDomain() {
            return domain;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        public String[] getNoProxy() {
            return noProxy;
        }
    }

}
