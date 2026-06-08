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
import io.smallrye.config.SmallRyeConfigBuilder;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class ProxyUtilTest {

    @Test
    public void fromConfigTest() {
        Assertions.assertNull(ProxyUtil.fromConfig(null));
        Assertions.assertNull(ProxyUtil.fromConfig(emptyConfig()));

        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.of(
                        AlpineConfigKeys.HTTP_PROXY_HOST, "proxy.http.example.com",
                        AlpineConfigKeys.HTTP_PROXY_PORT, "6666",
                        AlpineConfigKeys.HTTP_PROXY_USERNAME, "domain\\username",
                        AlpineConfigKeys.HTTP_PROXY_PASSWORD, "pa$%word",
                        AlpineConfigKeys.NO_PROXY, "acme.com,foo.bar:1234"))
                .build();

        final var proxyCfg = ProxyUtil.fromConfig(config);
        Assertions.assertNotNull(proxyCfg);
        Assertions.assertEquals("proxy.http.example.com", proxyCfg.getHost());
        Assertions.assertEquals(6666, proxyCfg.getPort());
        Assertions.assertEquals("domain", proxyCfg.getDomain());
        Assertions.assertEquals("username", proxyCfg.getUsername());
        Assertions.assertEquals("pa$%word", proxyCfg.getPassword());
        Assertions.assertEquals(Set.of("acme.com", "foo.bar:1234"), proxyCfg.getNoProxy());
    }

    @Test
    public void fromEnvironmentTest() {
        Assertions.assertNull(ProxyUtil.fromEnvironment(null));
        Assertions.assertNull(ProxyUtil.fromEnvironment(Collections.emptyMap()));

        final var proxyCfg = ProxyUtil.fromEnvironment(Map.of(
                "https_proxy", "http://proxy.https.example.com:6443",
                "http_proxy", "http://proxy.http.example.com:6666",
                "no_proxy", "acme.com,foo.bar:1234"
        ));
        Assertions.assertNotNull(proxyCfg);
        Assertions.assertEquals("proxy.https.example.com", proxyCfg.getHost());
        Assertions.assertEquals(6443, proxyCfg.getPort());
        Assertions.assertNull(proxyCfg.getDomain());
        Assertions.assertNull(proxyCfg.getUsername());
        Assertions.assertNull(proxyCfg.getPassword());
        Assertions.assertEquals(Set.of("acme.com", "foo.bar:1234"), proxyCfg.getNoProxy());
    }

    @Test
    public void fromEnvironmentWithAuthenticationTest() {
        final var proxyCfg = ProxyUtil.fromEnvironment(Map.of(
                "http_proxy", "http://domain%5Cusername:pa$%25word@proxy.http.example.com:6666"
        ));
        Assertions.assertNotNull(proxyCfg);
        Assertions.assertEquals("proxy.http.example.com", proxyCfg.getHost());
        Assertions.assertEquals(6666, proxyCfg.getPort());
        Assertions.assertEquals("domain", proxyCfg.getDomain());
        Assertions.assertEquals("username", proxyCfg.getUsername());
        Assertions.assertEquals("pa$%word", proxyCfg.getPassword());
        Assertions.assertNull(proxyCfg.getNoProxy());
    }

    private static Config emptyConfig() {
        return new SmallRyeConfigBuilder().build();
    }

}
