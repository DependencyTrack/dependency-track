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
package alpine.server.auth;

import alpine.config.AlpineConfigKeys;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.ldap.LLdapContainer;

import javax.naming.AuthenticationNotSupportedException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@Testcontainers
class LdapConnectionWrapperTest {

    @Container
    private static final LLdapContainer LDAP = new LLdapContainer("lldap/lldap:2026-03-04-alpine")
            .withUserPass("password")
            .withEnv("LLDAP_JWT_SECRET", "0123456789abcdef0123456789abcdef");

    @Test
    void shouldNotThrowNpeWhenBindCredentialsAreEmpty() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry(AlpineConfigKeys.LDAP_ENABLED, "true"),
                        Map.entry(AlpineConfigKeys.LDAP_SERVER_URL, LDAP.getLdapUrl()),
                        Map.entry(AlpineConfigKeys.LDAP_BASEDN, LDAP.getBaseDn()),
                        Map.entry(AlpineConfigKeys.LDAP_BIND_USERNAME, ""),
                        Map.entry(AlpineConfigKeys.LDAP_BIND_PASSWORD, ""),
                        Map.entry(AlpineConfigKeys.LDAP_NAME_ATTRIBUTE, "uid"),
                        Map.entry(AlpineConfigKeys.LDAP_MAIL_ATTRIBUTE, "mail"),
                        Map.entry(AlpineConfigKeys.LDAP_USER_PROVISIONING, "true"),
                        Map.entry(AlpineConfigKeys.LDAP_TEAM_SYNCHRONIZATION, "false")))
                .build();
        final var wrapper = new LdapConnectionWrapper(config);

        // LLDAP testcontainer doesn't support unauthenticated usage,
        // we assert whether authentication was *attempted* without credentials instead.
        assertThatExceptionOfType(AuthenticationNotSupportedException.class)
                .isThrownBy(wrapper::createDirContext)
                .withMessageContaining("error code 48");
    }

}
