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

import alpine.model.auth.ApiKeyPrincipal;
import alpine.model.auth.TeamRef;
import alpine.model.auth.UserPrincipal;
import alpine.model.auth.UserType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class PrincipalSecurityContextTest {

    private final UserPrincipal principal = new UserPrincipal(
            1L,
            "testuser",
            UserType.MANAGED,
            List.of(new TeamRef(2L, "team", UUID.randomUUID())),
            Set.of("BOM_UPLOAD", "VIEW_PORTFOLIO"));

    @Test
    void shouldExposeThePrincipalAndTheSchemeItAuthenticatedWith() {
        final var apiKeyPrincipal = new ApiKeyPrincipal(3L, "abcd1234", List.of(), Set.of("BOM_UPLOAD"));

        final var userContext =
                new PrincipalSecurityContext(principal, /* secure */ true, /* portfolioAccessControlEnabled */ false);
        assertThat(userContext.getUserPrincipal()).isSameAs(principal);
        assertThat(userContext.getAuthenticationScheme()).isEqualTo("BEARER");
        assertThat(userContext.isSecure()).isTrue();

        final var apiKeyContext = new PrincipalSecurityContext(
                apiKeyPrincipal, /* secure */ false, /* portfolioAccessControlEnabled */ true);
        assertThat(apiKeyContext.getUserPrincipal()).isSameAs(apiKeyPrincipal);
        assertThat(apiKeyContext.getAuthenticationScheme()).isEqualTo("API_KEY");
        assertThat(apiKeyContext.isSecure()).isFalse();
    }

    @Test
    void shouldRefuseRoleChecksEvenForPermissionsThePrincipalHas() {
        final var securityContext =
                new PrincipalSecurityContext(principal, /* secure */ false, /* portfolioAccessControlEnabled */ false);

        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> securityContext.isUserInRole("BOM_UPLOAD"));
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> securityContext.isUserInRole("VIEW_PORTFOLIO"));
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> securityContext.isUserInRole("NOT_A_PERMISSION"));
    }
}
