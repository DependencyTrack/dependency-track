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

package alpine.server.util;

import alpine.config.AlpineConfigKeys;
import alpine.server.auth.OidcConfiguration;
import alpine.server.auth.OidcConfigurationResolver;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

/**
 * @since 1.8.0
 */
public final class OidcUtil {

    private OidcUtil() {
    }

    /**
     * Determines whether or not the OpenID Connect integration is available.
     * <p>
     * Availability is given if OpenID Connect has been enabled via Alpine's configuration
     * <strong>and</strong> the configuration of the configured OpenID Connect identity provider
     * has been resolved successfully.
     *
     * @return {@code true} when OpenID Connect is available, otherwise {@code false}
     */
    public static boolean isOidcAvailable() {
        return isOidcAvailable(ConfigProvider.getConfig(), OidcConfigurationResolver.getInstance().resolve());
    }

    public static boolean isOidcAvailable(final Config config, final OidcConfiguration oidcConfiguration) {
        return config.getValue(AlpineConfigKeys.OIDC_ENABLED, Boolean.class)
                && oidcConfiguration != null;
    }

}
