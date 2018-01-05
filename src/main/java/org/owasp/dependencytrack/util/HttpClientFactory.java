/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.util;

import alpine.Config;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;

public final class HttpClientFactory {

    private static final String PROXY_ADDRESS = Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_ADDRESS);
    private static final int PROXY_PORT = Config.getInstance().getPropertyAsInt(Config.AlpineKey.HTTP_PROXY_PORT);
    private static final String PROXY_USERNAME = Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_USERNAME);
    private static final String PROXY_PASSWORD = Config.getInstance().getProperty(Config.AlpineKey.HTTP_PROXY_PASSWORD);

    private HttpClientFactory() { }

    public static HttpClient createClient() {
        HttpClientBuilder clientBuilder = HttpClientBuilder.create();
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        clientBuilder.useSystemProperties();
        if (StringUtils.isNotBlank(PROXY_ADDRESS) && PROXY_PORT > 0) {
            clientBuilder.setProxy(new HttpHost(PROXY_ADDRESS, PROXY_PORT));
            if (StringUtils.isNotBlank(PROXY_USERNAME) && StringUtils.isNotBlank(PROXY_PASSWORD)) {
                credsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(PROXY_USERNAME, PROXY_PASSWORD));
            }
        }
        clientBuilder.setDefaultCredentialsProvider(credsProvider);
        clientBuilder.setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
        Lookup<AuthSchemeProvider> authProviders = RegistryBuilder.<AuthSchemeProvider>create()
                .register(AuthSchemes.BASIC, new BasicSchemeFactory())
                .build();
        clientBuilder.setDefaultAuthSchemeRegistry(authProviders);
        return clientBuilder.build();
    }

}
