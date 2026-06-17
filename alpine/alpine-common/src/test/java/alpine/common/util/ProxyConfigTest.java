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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Set;

public class ProxyConfigTest {

    @Test
    public void shouldProxyWithoutHostTest() throws MalformedURLException {
        final var proxyCfg = new ProxyConfig();
        Assertions.assertFalse(proxyCfg.shouldProxy(null));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("ftp://example.com:21").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://example.com:443").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://example.com:8080").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://www.example.com:443").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://foo.example.com:80").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://fooexample.com:80").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://foo.bar.example.com:8000").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://www.example.net:80").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://foo.example.net:80").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://example.org:443").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://127.0.0.1:8080").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://127.0.0.1:8000").toURL()));
    }

    @Test
    public void shouldProxyWithoutNoProxyTest() throws MalformedURLException {
        final var proxyCfg = new ProxyConfig();
        proxyCfg.setHost("proxy.example.com");
        Assertions.assertFalse(proxyCfg.shouldProxy(null));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("ftp://example.com:21").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://example.com:443").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://example.com:8080").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://www.example.com:443").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://foo.example.com:80").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://fooexample.com:80").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://foo.bar.example.com:8000").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://www.example.net:80").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://foo.example.net:80").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://example.org:443").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://127.0.0.1:8080").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://127.0.0.1:8000").toURL()));
    }

    @Test
    public void shouldProxyWithNoProxyTest() throws MalformedURLException {
        final var proxyCfg = new ProxyConfig();
        proxyCfg.setHost("proxy.example.com");
        proxyCfg.setNoProxy(Set.of("localhost:443", "127.0.0.1:8080", "example.com", "www.example.net"));
        Assertions.assertFalse(proxyCfg.shouldProxy(null));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("ftp://example.com:21").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://example.com:443").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://example.com:8080").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://www.example.com:443").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://foo.example.com:80").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://fooexample.com:80").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://foo.bar.example.com:8000").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://www.example.net:80").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://foo.example.net:80").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://example.org:443").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://127.0.0.1:8080").toURL()));
        Assertions.assertTrue(proxyCfg.shouldProxy(URI.create("http://127.0.0.1:8000").toURL()));
    }

    @Test
    public void shouldProxyWithNoProxyStarTest() throws MalformedURLException {
        final var proxyCfg = new ProxyConfig();
        proxyCfg.setHost("proxy.example.com");
        proxyCfg.setNoProxy(Set.of("*"));
        Assertions.assertFalse(proxyCfg.shouldProxy(null));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("ftp://example.com:21").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://example.com:443").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://example.com:8080").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://www.example.com:443").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://foo.example.com:80").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://fooexample.com:80").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://foo.bar.example.com:8000").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://www.example.net:80").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://foo.example.net:80").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://example.org:443").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://127.0.0.1:8080").toURL()));
        Assertions.assertFalse(proxyCfg.shouldProxy(URI.create("http://127.0.0.1:8000").toURL()));
    }

}