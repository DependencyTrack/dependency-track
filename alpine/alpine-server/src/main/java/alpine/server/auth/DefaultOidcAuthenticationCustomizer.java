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
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import java.util.Arrays;
import java.util.Collection;

import static java.util.function.Predicate.not;

public class DefaultOidcAuthenticationCustomizer implements OidcAuthenticationCustomizer {

    private final String usernameClaimName;
    private final String teamsClaimName;

    @SuppressWarnings("unused") // Used by ServiceLoader.
    public DefaultOidcAuthenticationCustomizer() {
        this(usernameClaim(ConfigProvider.getConfig()), teamsClaim(ConfigProvider.getConfig()));
    }

    private static String usernameClaim(final Config config) {
        return config.getOptionalValue(AlpineConfigKeys.OIDC_USERNAME_CLAIM, String.class).orElse(null);
    }

    private static String teamsClaim(final Config config) {
        return config.getOptionalValue(AlpineConfigKeys.OIDC_TEAMS_CLAIM, String.class).orElse(null);
    }

    DefaultOidcAuthenticationCustomizer(final String usernameClaimName, final String teamsClaimName) {
        this.usernameClaimName = usernameClaimName;
        this.teamsClaimName = teamsClaimName;
    }

    @Override
    public OidcProfile createProfile(ClaimsSet claimsSet) {
        final var profile = new OidcProfile();

        profile.setSubject(claimsSet.getStringClaim(UserInfo.SUB_CLAIM_NAME));
        profile.setUsername(claimsSet.getStringClaim(usernameClaimName));
        final Object groupsClaim = teamsClaimName != null
                ? claimsSet.getClaim(teamsClaimName)
                : null;
        profile.setGroups(switch (groupsClaim) {
            case String groupsString -> Arrays.stream(groupsString.split(","))
                    .map(String::trim)
                    .filter(not(String::isEmpty))
                    .toList();
            case Collection<?> _ -> claimsSet.getStringListClaim(teamsClaimName);
            case null, default -> null;
        });
        profile.setEmail(claimsSet.getStringClaim(UserInfo.EMAIL_CLAIM_NAME));

        JSONObject claimsObj = claimsSet.toJSONObject();
        claimsObj.remove(UserInfo.EMAIL_CLAIM_NAME);
        claimsObj.remove(UserInfo.SUB_CLAIM_NAME);
        claimsObj.remove(teamsClaimName);
        claimsObj.remove(usernameClaimName);

        profile.setCustomValues(claimsObj);

        return profile;
    }

    @Override
    public boolean isProfileComplete(final OidcProfile profile, final boolean teamSyncEnabled) {
        return profile.getSubject() != null && profile.getUsername() != null
                && (!teamSyncEnabled || (profile.getGroups() != null));
    }

    @Override
    public OidcProfile mergeProfiles(final OidcProfile left, final OidcProfile right) {
        final var profile = new OidcProfile();

        profile.setSubject(selectProfileClaim(left.getSubject(), right.getSubject()));
        profile.setUsername(selectProfileClaim(left.getUsername(), right.getUsername()));
        profile.setGroups(selectProfileClaim(left.getGroups(), right.getGroups()));
        profile.setEmail(selectProfileClaim(left.getEmail(), right.getEmail()));

        JSONObject customValues = left.getCustomValues();
        customValues.merge(right.getCustomValues());
        profile.setCustomValues(customValues);

        return profile;
    }

    @Override
    public OidcUser onAuthenticationSuccess(OidcUser user, OidcProfile profile, String idToken, String accessToken) {
        return user;
    }

    private <T> T selectProfileClaim(final T left, final T right) {
        return (left != null) ? left : right;
    }

}
