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
package alpine.server.auth;

import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultOidcAuthenticationCustomizerTest {

    @Nested
    class CreateProfileTest {

        @Test
        void shouldCreateProfile() {
            final var customizer = new DefaultOidcAuthenticationCustomizer("username", "groups");

            final var claims = new ClaimsSet(
                    new JSONObject(
                            Map.ofEntries(
                                    Map.entry("sub", "subject-foo"),
                                    Map.entry("username", "username"),
                                    Map.entry("email", "user@example.com"),
                                    Map.entry("groups", List.of("group-foo")))));

            final OidcProfile profile = customizer.createProfile(claims);
            assertThat(profile).isNotNull();
            assertThat(profile.getSubject()).isEqualTo("subject-foo");
            assertThat(profile.getUsername()).isEqualTo("username");
            assertThat(profile.getEmail()).isEqualTo("user@example.com");
            assertThat(profile.getGroups()).containsOnly("group-foo");
        }

        @Test
        void shouldSupportTeamsClaimAsString() {
            final var customizer = new DefaultOidcAuthenticationCustomizer("username", "groups");

            final var claims = new ClaimsSet(
                    new JSONObject(
                            Map.ofEntries(
                                    Map.entry("sub", "subject-foo"),
                                    Map.entry("username", "username"),
                                    Map.entry("email", "user@example.com"),
                                    Map.entry("groups", "group-foo"))));

            final OidcProfile profile = customizer.createProfile(claims);
            assertThat(profile).isNotNull();
            assertThat(profile.getSubject()).isEqualTo("subject-foo");
            assertThat(profile.getUsername()).isEqualTo("username");
            assertThat(profile.getEmail()).isEqualTo("user@example.com");
            assertThat(profile.getGroups()).containsOnly("group-foo");
        }

        @Test
        void shouldSupportTeamsClaimAsDelimitedString() {
            final var customizer = new DefaultOidcAuthenticationCustomizer("username", "groups");

            final var claims = new ClaimsSet(
                    new JSONObject(
                            Map.ofEntries(
                                    Map.entry("sub", "subject-foo"),
                                    Map.entry("username", "username"),
                                    Map.entry("email", "user@example.com"),
                                    Map.entry("groups", "group-foo, group-bar"))));

            final OidcProfile profile = customizer.createProfile(claims);
            assertThat(profile).isNotNull();
            assertThat(profile.getSubject()).isEqualTo("subject-foo");
            assertThat(profile.getUsername()).isEqualTo("username");
            assertThat(profile.getEmail()).isEqualTo("user@example.com");
            assertThat(profile.getGroups()).containsOnly("group-foo", "group-bar");
        }

        @Test
        void shouldLeaveGroupsNullWhenTeamsClaimIsAbsent() {
            final var customizer = new DefaultOidcAuthenticationCustomizer("username", "groups");

            final var claims = new ClaimsSet(
                    new JSONObject(
                            Map.ofEntries(
                                    Map.entry("sub", "subject-foo"),
                                    Map.entry("username", "username"),
                                    Map.entry("email", "user@example.com"))));

            final OidcProfile profile = customizer.createProfile(claims);
            assertThat(profile).isNotNull();
            assertThat(profile.getSubject()).isEqualTo("subject-foo");
            assertThat(profile.getUsername()).isEqualTo("username");
            assertThat(profile.getEmail()).isEqualTo("user@example.com");
            assertThat(profile.getGroups()).isNull();
        }

        @Test
        void shouldLeaveGroupsNullWhenTeamsClaimNameIsNotConfigured() {
            final var customizer = new DefaultOidcAuthenticationCustomizer("username", null);

            final var claims = new ClaimsSet(
                    new JSONObject(
                            Map.ofEntries(
                                    Map.entry("sub", "subject-foo"),
                                    Map.entry("username", "username"),
                                    Map.entry("email", "user@example.com"),
                                    Map.entry("groups", List.of("group-foo")))));

            final OidcProfile profile = customizer.createProfile(claims);
            assertThat(profile).isNotNull();
            assertThat(profile.getGroups()).isNull();
        }

        @Test
        void shouldReturnEmptyGroupsWhenTeamsClaimIsPresentButEmptyString() {
            final var customizer = new DefaultOidcAuthenticationCustomizer("username", "groups");

            final var claims = new ClaimsSet(
                    new JSONObject(
                            Map.ofEntries(
                                    Map.entry("sub", "subject-foo"),
                                    Map.entry("username", "username"),
                                    Map.entry("email", "user@example.com"),
                                    Map.entry("groups", ""))));

            final OidcProfile profile = customizer.createProfile(claims);
            assertThat(profile).isNotNull();
            assertThat(profile.getGroups()).isNotNull().isEmpty();
        }

        @Test
        void shouldReturnEmptyGroupsWhenTeamsClaimIsPresentButEmptyList() {
            final var customizer = new DefaultOidcAuthenticationCustomizer("username", "groups");

            final var claims = new ClaimsSet(
                    new JSONObject(
                            Map.ofEntries(
                                    Map.entry("sub", "subject-foo"),
                                    Map.entry("username", "username"),
                                    Map.entry("email", "user@example.com"),
                                    Map.entry("groups", List.of()))));

            final OidcProfile profile = customizer.createProfile(claims);
            assertThat(profile).isNotNull();
            assertThat(profile.getGroups()).isNotNull().isEmpty();
        }

    }

}