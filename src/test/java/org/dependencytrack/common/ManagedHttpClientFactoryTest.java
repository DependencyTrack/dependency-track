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
import alpine.util.SystemUtil;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

public class ManagedHttpClientFactoryTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Before
    public void before() {
        environmentVariables.set("http_proxy", "http://acme\\username:password@127.0.0.1:1080");
        environmentVariables.set("no_proxy", "localhost:443,127.0.0.1:8080");
    }

    @Test
    public void instanceTest() {
        HttpClient c1 = ManagedHttpClientFactory.newManagedHttpClient().getHttpClient();
        HttpClient c2 = ManagedHttpClientFactory.newManagedHttpClient().getHttpClient();
        Assert.assertNotSame(c1, c2);
        Assert.assertTrue(c1 instanceof CloseableHttpClient);
    }

    @Test
    public void proxyIntoTest() {
        ManagedHttpClientFactory.ProxyInfo proxyInfo = ManagedHttpClientFactory.createProxyInfo();
        Assert.assertEquals("127.0.0.1", proxyInfo.getHost());
        Assert.assertEquals(1080, proxyInfo.getPort());
        Assert.assertEquals("acme", proxyInfo.getDomain());
        Assert.assertEquals("username", proxyInfo.getUsername());
        Assert.assertEquals("password", proxyInfo.getPassword());
        Assert.assertArrayEquals(new String[]{"localhost:443", "127.0.0.1:8080"}, proxyInfo.getNoProxy());
    }

    @Test
    public void userAgentTest() {
        String expected = Config.getInstance().getApplicationName()
                + " v" + Config.getInstance().getApplicationVersion()
                + " ("
                + SystemUtil.getOsArchitecture() + "; "
                + SystemUtil.getOsName() + "; "
                + SystemUtil.getOsVersion()
                + ")";
        Assert.assertEquals(expected, ManagedHttpClientFactory.getUserAgent());
    }
}
