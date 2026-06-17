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

import alpine.config.AlpineConfigKeys;
import alpine.model.OidcUser;
import alpine.persistence.AlpineQueryManager;
import alpine.server.util.OidcUtil;
import jakarta.annotation.Nonnull;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * @since 1.8.0
 */
public class OidcAuthenticationService implements AuthenticationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(OidcAuthenticationService.class);

    private final Config config;
    private final OidcConfiguration oidcConfiguration;
    private final OidcIdTokenAuthenticator idTokenAuthenticator;
    private final OidcUserInfoAuthenticator userInfoAuthenticator;
    private final String idToken;
    private final String accessToken;
    private final OidcAuthenticationCustomizer customizer;

    /**
     * @param accessToken The access token acquired by authenticating with an IdP
     * @deprecated Use {@link #OidcAuthenticationService(String, String)} instead
     */
    @Deprecated
    public OidcAuthenticationService(final String accessToken) {
        this(ConfigProvider.getConfig(), OidcConfigurationResolver.getInstance().resolve(), null, accessToken);
    }

    /**
     * @param idToken     The ID token acquired by authenticating with an IdP
     * @param accessToken The access token acquired by authenticating with an IdP
     * @since 1.10.0
     */
    public OidcAuthenticationService(final String idToken, final String accessToken) {
        this(ConfigProvider.getConfig(), OidcConfigurationResolver.getInstance().resolve(), idToken, accessToken);
    }

    /**
     * Constructor for unit tests
     */
    OidcAuthenticationService(final Config config, final OidcConfiguration oidcConfiguration, final String idToken, final String accessToken) {
        this(config, oidcConfiguration, new OidcIdTokenAuthenticator(oidcConfiguration, config.getOptionalValue(AlpineConfigKeys.OIDC_CLIENT_ID, String.class).orElse(null)), new OidcUserInfoAuthenticator(oidcConfiguration), idToken, accessToken);
    }

    /**
     * Constructor for unit tests
     *
     * @since 1.10.0
     */
    OidcAuthenticationService(final Config config,
                              final OidcConfiguration oidcConfiguration,
                              final OidcIdTokenAuthenticator idTokenAuthenticator,
                              final OidcUserInfoAuthenticator userInfoAuthenticator,
                              final String idToken,
                              final String accessToken) {
        this.config = config;
        this.oidcConfiguration = oidcConfiguration;
        this.idTokenAuthenticator = idTokenAuthenticator;
        this.userInfoAuthenticator = userInfoAuthenticator;
        this.idToken = idToken;
        this.accessToken = accessToken;

        final String customizerClassName = config.getValue(AlpineConfigKeys.OIDC_AUTH_CUSTOMIZER, String.class);
        this.customizer = ServiceLoader.load(OidcAuthenticationCustomizer.class)
                .stream()
                .filter(provider -> provider.type().getName().equals(customizerClassName))
                .map(ServiceLoader.Provider::get)
                .findFirst()
                .orElseThrow(IllegalStateException::new);
    }

    @Override
    public boolean isSpecified() {
        return OidcUtil.isOidcAvailable(config, oidcConfiguration)
                && (accessToken != null || idToken != null);
    }

    /**
     * Authenticate a {@link Principal} using the provided credentials.
     * <p>
     * If an ID token is provided, Alpine will validate it and source configured claims from it.
     * <p>
     * If an access token is provided, Alpine will call the IdP's {@code /userinfo} endpoint with it
     * to verify its validity, and source configured claims from the response.
     * <p>
     * If both access token and ID token are provided, the ID token takes precedence.
     * When all configured claims are found in the ID token, {@code /userinfo} won't be requested.
     * When not all claims were found in the ID token, {@code /userinfo} will be requested supplementary.
     *
     * @return An authenticated {@link Principal}
     * @throws AlpineAuthenticationException When authentication failed
     */
    @Nonnull
    @Override
    public Principal authenticate() throws AlpineAuthenticationException {
        final String usernameClaimName = config.getOptionalValue(AlpineConfigKeys.OIDC_USERNAME_CLAIM, String.class).orElse(null);
        if (usernameClaimName == null) {
            LOGGER.error("No username claim has been configured");
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.OTHER);
        }

        final boolean teamSyncEnabled = config.getValue(AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, Boolean.class);
        final String teamsClaimName = config.getOptionalValue(AlpineConfigKeys.OIDC_TEAMS_CLAIM, String.class).orElse(null);
        if (teamSyncEnabled && teamsClaimName == null) {
            LOGGER.error("Team synchronization is enabled, but no teams claim has been configured");
            throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.OTHER);
        }

        final OidcProfileCreator profileCreator = customizer::createProfile;

        OidcProfile idTokenProfile = null;
        if (idToken != null) {
            idTokenProfile = idTokenAuthenticator.authenticate(idToken, profileCreator);
            LOGGER.debug("ID token profile: {}", idTokenProfile);

            if (customizer.isProfileComplete(idTokenProfile, teamSyncEnabled)) {
                LOGGER.debug("ID token profile is complete, proceeding to authenticate");
                return authenticateInternal(idTokenProfile);
            }
        }

        OidcProfile userInfoProfile = null;
        if (accessToken != null) {
            userInfoProfile = userInfoAuthenticator.authenticate(accessToken, profileCreator);
            LOGGER.debug("UserInfo profile: {}", userInfoProfile);

            if (customizer.isProfileComplete(userInfoProfile, teamSyncEnabled)) {
                LOGGER.debug("UserInfo profile is complete, proceeding to authenticate");
                return authenticateInternal(userInfoProfile);
            }
        }

        OidcProfile mergedProfile = null;
        if (idTokenProfile != null && userInfoProfile != null) {
            mergedProfile = customizer.mergeProfiles(idTokenProfile, userInfoProfile);
            LOGGER.debug("Merged profile: {}", mergedProfile);

            if (customizer.isProfileComplete(mergedProfile, teamSyncEnabled)) {
                LOGGER.debug("Merged profile is complete, proceeding to authenticate");
                return authenticateInternal(mergedProfile);
            }
        }

        LOGGER.error("Unable to assemble complete profile (ID token: {}, UserInfo: {}, Merged: {})", idTokenProfile, userInfoProfile, mergedProfile);
        throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.OTHER);
    }

    private OidcUser authenticateInternal(final OidcProfile profile) throws AlpineAuthenticationException {
        try (final var qm = new AlpineQueryManager()) {
            OidcUser user = qm.getOidcUser(profile.getUsername());
            if (user != null) {
                LOGGER.debug("Attempting to authenticate user: {}", user.getUsername());
                if (user.getSubjectIdentifier() == null) {
                    LOGGER.debug("Assigning subject identifier {} to user {}", profile.getSubject(), user.getUsername());
                    user.setSubjectIdentifier(profile.getSubject());
                    user.setEmail(profile.getEmail());

                    return customizer.onAuthenticationSuccess(qm.updateOidcUser(user), profile, idToken, accessToken);
                } else if (!user.getSubjectIdentifier().equals(profile.getSubject())) {
                    LOGGER.error("Refusing to authenticate user {}: subject identifier has changed ({} to {})", user.getUsername(), user.getSubjectIdentifier(), profile.getSubject());
                    throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.INVALID_CREDENTIALS);
                }

                if (!Objects.equals(user.getEmail(), profile.getEmail())) {
                    LOGGER.debug("Updating email of user {}: {} -> {}", user.getUsername(), user.getEmail(), profile.getEmail());
                    user.setEmail(profile.getEmail());
                    user = qm.updateOidcUser(user);
                }

                if (config.getValue(AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, Boolean.class)) {
                    return customizer.onAuthenticationSuccess(
                            qm.synchronizeTeamMembership(user, profile.getGroups()),
                            profile,
                            idToken,
                            accessToken);
                }

                return customizer.onAuthenticationSuccess(user, profile, idToken, accessToken);
            } else if (config.getValue(AlpineConfigKeys.OIDC_USER_PROVISIONING, Boolean.class)) {
                LOGGER.debug("The user ({}) authenticated successfully but the account has not been provisioned", profile.getUsername());
                return autoProvision(qm, profile);
            } else {
                LOGGER.debug("The user ({}) is unmapped and user provisioning is not enabled", profile.getUsername());
                throw new AlpineAuthenticationException(AlpineAuthenticationException.CauseType.UNMAPPED_ACCOUNT);
            }
        }
    }

    private OidcUser autoProvision(final AlpineQueryManager qm, final OidcProfile profile) {
        var user = new OidcUser();
        user.setUsername(profile.getUsername());
        user.setSubjectIdentifier(profile.getSubject());
        user.setEmail(profile.getEmail());
        user = qm.persist(user);

        if (config.getValue(AlpineConfigKeys.OIDC_TEAM_SYNCHRONIZATION, Boolean.class)) {
            LOGGER.debug("Synchronizing teams for user {}", user.getUsername());
            return customizer.onAuthenticationSuccess(
                    qm.synchronizeTeamMembership(user, profile.getGroups()),
                    profile,
                    idToken,
                    accessToken);
        }

        final List<String> defaultTeams = config.getOptionalValues(AlpineConfigKeys.OIDC_DEFAULT_TEAMS, String.class)
                .orElse(List.of()).stream()
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
        if (!defaultTeams.isEmpty()) {
            LOGGER.debug("Assigning default teams %s to user %s".formatted(defaultTeams, user.getUsername()));
            return customizer.onAuthenticationSuccess(
                    qm.addUserToTeams(user, defaultTeams),
                    profile,
                    idToken,
                    accessToken);
        }

        return user;
    }

}
