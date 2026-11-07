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
package org.dependencytrack.auth.saml;

import org.dependencytrack.common.ConfigKeys;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/// Configuration of the SAML service provider.
///
/// @since 5.3.0
public record SamlConfig(
        String spEntityId,
        URI acsUrl,
        URI frontendUrl,
        @Nullable URI idpMetadataUrl,
        @Nullable Path idpMetadataFile,
        @Nullable String usernameAttribute,
        @Nullable String emailAttribute,
        @Nullable String groupsAttribute,
        boolean userProvisioning,
        boolean teamSynchronization,
        boolean groupProvisioning,
        List<String> defaultTeams) {

    static final String ENABLED = "dt.saml.enabled";
    static final String SP_ENTITY_ID = "dt.saml.sp.entity-id";
    static final String SP_ACS_URL = "dt.saml.sp.acs-url";
    static final String FRONTEND_URL = ConfigKeys.FRONTEND_URL;
    static final String IDP_METADATA_URL = "dt.saml.idp.metadata-url";
    static final String IDP_METADATA_FILE = "dt.saml.idp.metadata-file";
    static final String USERNAME_ATTRIBUTE = "dt.saml.username-attribute";
    static final String EMAIL_ATTRIBUTE = "dt.saml.email-attribute";
    static final String GROUPS_ATTRIBUTE = "dt.saml.groups-attribute";
    static final String USER_PROVISIONING = "dt.saml.user-provisioning";
    static final String TEAM_SYNCHRONIZATION = "dt.saml.team-synchronization";
    static final String GROUP_PROVISIONING = "dt.saml.group-provisioning";
    static final String DEFAULT_TEAMS = "dt.saml.default-teams";

    public SamlConfig {
        defaultTeams = List.copyOf(defaultTeams);
    }

    /// Loads the configuration.
    ///
    /// @return The configuration, or empty when SAML is disabled.
    /// @throws IllegalStateException When SAML is enabled, but the configuration is incomplete or invalid.
    public static Optional<SamlConfig> load(Config config) {
        if (!config.getOptionalValue(ENABLED, boolean.class).orElse(false)) {
            return Optional.empty();
        }

        final URI idpMetadataUrl = optionalString(config, IDP_METADATA_URL)
                .map(value -> requireAbsoluteHttpUri(IDP_METADATA_URL, value))
                .orElse(null);
        final Path idpMetadataFile =
                optionalString(config, IDP_METADATA_FILE).map(Path::of).orElse(null);
        if ((idpMetadataUrl == null) == (idpMetadataFile == null)) {
            throw new IllegalStateException(
                    "Exactly one of %s and %s must be set".formatted(IDP_METADATA_URL, IDP_METADATA_FILE));
        }

        final boolean teamSynchronization =
                config.getOptionalValue(TEAM_SYNCHRONIZATION, boolean.class).orElse(false);
        final boolean groupProvisioning =
                config.getOptionalValue(GROUP_PROVISIONING, boolean.class).orElse(false);
        final String groupsAttribute = optionalString(config, GROUPS_ATTRIBUTE).orElse(null);
        if ((teamSynchronization || groupProvisioning) && groupsAttribute == null) {
            throw new IllegalStateException("%s must be set when %s or %s is enabled"
                    .formatted(GROUPS_ATTRIBUTE, TEAM_SYNCHRONIZATION, GROUP_PROVISIONING));
        }

        return Optional.of(new SamlConfig(
                requireString(config, SP_ENTITY_ID),
                requireAbsoluteHttpUri(SP_ACS_URL, requireString(config, SP_ACS_URL)),
                requireAbsoluteHttpUri(FRONTEND_URL, requireString(config, FRONTEND_URL)),
                idpMetadataUrl,
                idpMetadataFile,
                optionalString(config, USERNAME_ATTRIBUTE).orElse(null),
                optionalString(config, EMAIL_ATTRIBUTE).orElse(null),
                groupsAttribute,
                config.getOptionalValue(USER_PROVISIONING, boolean.class).orElse(false),
                teamSynchronization,
                groupProvisioning,
                config.getOptionalValues(DEFAULT_TEAMS, String.class).orElse(List.of()).stream()
                        .map(String::trim)
                        .filter(team -> !team.isEmpty())
                        .toList()));
    }

    private static Optional<String> optionalString(Config config, String name) {
        return config.getOptionalValue(name, String.class).map(String::trim).filter(value -> !value.isEmpty());
    }

    private static String requireString(Config config, String name) {
        return optionalString(config, name)
                .orElseThrow(() -> new IllegalStateException("%s must be set".formatted(name)));
    }

    private static URI requireAbsoluteHttpUri(String name, String value) {
        final URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("%s is not a valid URL".formatted(name), e);
        }
        if ((!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme())) || uri.getHost() == null) {
            throw new IllegalStateException("%s must be an absolute http or https URL".formatted(name));
        }
        return uri;
    }
}
