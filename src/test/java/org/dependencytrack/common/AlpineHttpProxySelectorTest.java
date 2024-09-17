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
import org.junit.Test;

import java.net.Proxy;
import java.net.URI;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class AlpineHttpProxySelectorTest {

    @Test
    public void testSelect() {
        final var proxyConfig = new ProxyConfig();
        proxyConfig.setHost("example.com");
        proxyConfig.setPort(6666);
        proxyConfig.setNoProxy(Set.of("subdomain.example.com"));

        final var proxySelector = new AlpineHttpProxySelector(proxyConfig);
        assertThat(proxySelector.select(URI.create("https://subdomain.example.com"))).containsOnly(Proxy.NO_PROXY);
        assertThat(proxySelector.select(URI.create("https://foo.example.com"))).containsOnly(proxyConfig.getProxy());
    }

}